"""Persistent local inference over the exact trained conditional projection."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import re
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

FORMAT = "contextdb.kev-worker.rendered-closure.v1"
MAX_META = 16 << 10
MAX_INPUT = 2 << 20
MAX_FRAME = 2 + MAX_META + MAX_INPUT
MAX_TIMEOUT = 30_000_000
MAX_STARTUP = 300_000_000
MAX_LOGIT = 1_000_000
SOURCE_SHA256 = {
    "corpus.py": "a5402749e8e2b9ae06606f0e41ded051addf85957b1a3c34add76d934d86fc12",
    "trainer.py": "bb00cfa6ebfa2d956edc5262ceafdf497e881d8a048745479a47a238c31594cc",
    "check.py": "5a37ce05d39df1aca2c6db1ad8a51a2c057dddcc3007d960451959a70725df14",
    "conditional.py": "b3c24f5dfdda29465f4b5cc4d2d0a73a7d3ee44cb312ee2437f4cca57a910827",
}
ERRORS = {"protocol_refused", "startup_refused", "projection_refused", "token_refused",
          "deadline_refused", "resource_refused", "inference_refused", "nonfinite_score"}


class WorkerFault(Exception):
    def __init__(self, code):
        if code not in ERRORS:
            code = "inference_refused"
        self.code = code
        super().__init__(code)


def require(condition, code="protocol_refused"):
    if not condition:
        raise WorkerFault(code)


def digest(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value))
    return value


def integer(value, maximum, minimum=0):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def check_deadline(deadline):
    require(time.monotonic() < deadline, "deadline_refused")


def strict_json(data, maximum):
    """Admit bytes/depth before JSON allocation; never include payload in errors."""
    require(type(data) is bytes and 0 < len(data) <= maximum)
    try:
        value = data.decode("utf-8", errors="strict")
        depth, quoted, escaped, structural = 0, False, False, 0
        for char in value:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                structural += 1
                require(depth <= 32)
            elif char in "]}":
                depth -= 1
                require(depth >= 0)
            elif char in ",:":
                structural += 1
            require(structural <= 131072)
        require(depth == 0 and not quoted)

        def pairs(entries):
            result = {}
            for key, item in entries:
                require(key not in result)
                result[key] = item
            return result

        def number(text):
            require(len(text) <= 21)
            item = int(text)
            require(-(1 << 63) <= item < 1 << 64)
            return item

        def forbidden(_):
            raise WorkerFault("protocol_refused")

        result = json.loads(value, object_pairs_hook=pairs, parse_int=number,
                            parse_float=forbidden, parse_constant=forbidden)
        pending, nodes = [(result, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(nodes <= 65536 and depth <= 32)
            if type(item) is dict:
                require(len(item) <= 128)
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                require(len(item) <= 1024)
                pending.extend((child, depth + 1) for child in item)
            elif type(item) is str:
                item.encode("utf-8", errors="strict")
        return result
    except WorkerFault:
        raise
    except MemoryError:
        raise WorkerFault("resource_refused") from None
    except Exception:
        raise WorkerFault("protocol_refused") from None


def read_exact(stream, count):
    output = bytearray()
    while len(output) < count:
        part = stream.read(count - len(output))
        require(part is not None and part)
        output.extend(part)
    return bytes(output)


@dataclass(repr=False)
class Frame:
    metadata: dict
    payload: bytes
    received_at: float

    def __repr__(self):
        return f"Frame(input_bytes={len(self.payload)})"


def read_frame(stream, validate=None):
    first = stream.read(1)
    if first == b"":
        return None
    require(first is not None)
    started = time.monotonic()  # Idle time before the first byte is not request time.
    size = struct.unpack(">I", first + read_exact(stream, 3))[0]
    require(2 < size <= MAX_FRAME)
    metadata_size = struct.unpack(">H", read_exact(stream, 2))[0]
    require(0 < metadata_size <= MAX_META and metadata_size <= size - 2)
    metadata = strict_json(read_exact(stream, metadata_size), MAX_META)
    require(type(metadata) is dict)
    payload_size = size - 2 - metadata_size
    require(payload_size <= MAX_INPUT)
    if validate is not None:
        validate(metadata, payload_size)
    return Frame(metadata, read_exact(stream, payload_size), started)


def write_frame(stream, metadata):
    encoded = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    require(0 < len(encoded) <= MAX_META - 2)
    for part in (struct.pack(">IH", len(encoded) + 2, len(encoded)), encoded):
        view = memoryview(part)
        while view:
            written = stream.write(view)
            require(type(written) is int and 0 < written <= len(view))
            view = view[written:]
    stream.flush()


def validate_request(metadata, payload_size, last_id, config_sha256):
    require(set(metadata) == {"format", "operation", "id", "config_sha256", "input_bytes",
                              "input_sha256", "timeout_micros"})
    require(metadata["format"] == FORMAT and metadata["operation"] == "score")
    require(integer(metadata["id"], (1 << 64) - 1, 1) == last_id + 1)
    require(digest(metadata["config_sha256"]) == config_sha256)
    digest(metadata["input_sha256"])
    require(integer(metadata["input_bytes"], MAX_INPUT, 1) == payload_size)
    integer(metadata["timeout_micros"], MAX_TIMEOUT, 1)


def score_frame(frame, backend):
    metadata = frame.metadata
    deadline = frame.received_at + metadata["timeout_micros"] / 1_000_000
    check_deadline(deadline)
    require(hashlib.sha256(frame.payload).hexdigest() == metadata["input_sha256"])
    value = strict_json(frame.payload, MAX_INPUT)
    check_deadline(deadline)
    score = backend.score(value, deadline)
    check_deadline(deadline)
    require(type(score) is float and math.isfinite(score) and abs(score) <= MAX_LOGIT,
            "nonfinite_score")
    return score


def serve(input_stream, output_stream, backend, config_sha256):
    """One request at a time; a failed request invalidates this child."""
    last_id = 0
    while True:
        frame = read_frame(input_stream, lambda meta, size:
                           validate_request(meta, size, last_id, config_sha256))
        if frame is None:
            return 0
        metadata = frame.metadata
        reply = {"format": FORMAT, "operation": "score", "id": metadata["id"],
                 "config_sha256": config_sha256, "input_sha256": metadata["input_sha256"]}
        try:
            score = score_frame(frame, backend)
            reply.update(status="ok", yes_minus_no=score)
        except BaseException as error:
            if isinstance(error, WorkerFault) and error.code == "protocol_refused":
                raise
            code = error.code if isinstance(error, WorkerFault) else (
                "resource_refused" if isinstance(error, MemoryError) else "inference_refused")
            reply.update(status="error", code=code)
            write_frame(output_stream, reply)
            return 2
        write_frame(output_stream, reply)
        last_id = metadata["id"]
        del frame, reply


def file_sha256(path, maximum):
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and not path.is_symlink() and path.stat().st_size <= maximum, "startup_refused")
    result = hashlib.sha256()
    admitted = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(1 << 20, maximum - admitted + 1))
            if not chunk:
                break
            admitted += len(chunk)
            require(admitted <= maximum, "startup_refused")
            result.update(chunk)
    return result.hexdigest()


def pinned_modules():
    """Check consumed tool sources before importing them, including Python -I."""
    directory = Path(__file__).absolute().parent
    require(directory.resolve() == directory, "startup_refused")
    for name, expected in SOURCE_SHA256.items():
        require(file_sha256(directory / name, 1 << 20) == expected, "startup_refused")
    sys.path.insert(0, str(directory))
    modules = {}
    for name in ("corpus", "trainer", "conditional"):
        module = importlib.import_module(name)
        require(Path(module.__file__).resolve() == directory / (name + ".py"), "startup_refused")
        modules[name] = module
    return modules["trainer"], modules["conditional"]


class ModelBackend:
    def __init__(self, torch, tokenizer, model, trainer, conditional):
        self.torch, self.tokenizer, self.model = torch, tokenizer, model
        self.trainer, self.conditional = trainer, conditional

    def score(self, input_value, deadline):
        check_deadline(deadline)
        try:
            state, question = self.conditional.project(input_value)
        except MemoryError:
            raise WorkerFault("resource_refused") from None
        except Exception:
            raise WorkerFault("projection_refused") from None
        check_deadline(deadline)
        example = SimpleNamespace(record={"state": state, "questions": [question]}, known=[True])
        try:
            encoded = self.trainer.encode_all(self.model, self.tokenizer, [example],
                                              self.conditional.LIMITS)[0]
        except MemoryError:
            raise WorkerFault("resource_refused") from None
        except Exception:
            raise WorkerFault("token_refused") from None
        check_deadline(deadline)
        try:
            with self.torch.no_grad():
                scores = self.trainer.utility_logits(self.torch, self.model, encoded)
                require(scores.shape == (1,), "nonfinite_score")
                result = float(scores[0].item())
        except WorkerFault:
            raise
        except MemoryError:
            raise WorkerFault("resource_refused") from None
        except Exception:
            raise WorkerFault("inference_refused") from None
        check_deadline(deadline)
        return result


def admit(args):
    started = time.monotonic()
    integer(args.startup_timeout_micros, MAX_STARTUP, 1)
    deadline = started + args.startup_timeout_micros / 1_000_000
    for item in (args.bundle_sha256, args.config_sha256, args.worker_sha256):
        digest(item)
    actual_worker = file_sha256(Path(__file__).absolute(), 1 << 20)
    require(actual_worker == args.worker_sha256, "startup_refused")
    trainer, conditional = pinned_modules()
    output_root = trainer.checked_root(args.output_root)
    path = trainer.run_path(output_root, args.run_name)
    bundle, profile = trainer.inspect_bundle(path, output_root, completed=True,
                                             profile_name=conditional.PROFILE)
    require(file_sha256(path / "bundle.json", 64 << 10) == args.bundle_sha256, "startup_refused")
    paths, pin = trainer.provenance(args.model_lock, conditional.PROFILE)
    trainer.verify_recorded_pin(profile, pin)
    require(pin["tool_sources_sha256"] == SOURCE_SHA256, "startup_refused")
    check_deadline(deadline)
    examples, _ = conditional.load_examples(args.corpus, profile["seed"])
    reference = trainer.cold_reference(path, conditional.LIMITS)
    example = next((item for item in examples if item.partition == "validation"
                    and item.association == reference["association"]), None)
    require(example is not None and len(example.known) == len(reference["utility_logits"]),
            "startup_refused")
    check_deadline(deadline)
    torch, tokenizer, model, _, _ = trainer.load_model(profile["seed"], paths)
    trainer.reload_bundle(torch, model, path, output_root, conditional.PROFILE)
    model.eval()
    model.head.temperature = 1.0
    check_deadline(deadline)
    with torch.no_grad():
        encoded = trainer.encode_all(model, tokenizer, [example], conditional.LIMITS)[0]
        actual = trainer.utility_logits(torch, model, encoded).cpu()
    expected = torch.tensor(reference["utility_logits"], dtype=actual.dtype)
    require(torch.equal(actual, expected), "startup_refused")
    check_deadline(deadline)
    require(file_sha256(path / "bundle.json", 64 << 10) == args.bundle_sha256
            and file_sha256(Path(__file__).absolute(), 1 << 20) == args.worker_sha256,
            "startup_refused")
    ready = {"format": FORMAT, "operation": "ready", "status": "ready",
             "config_sha256": args.config_sha256, "bundle_sha256": args.bundle_sha256,
             "worker_sha256": actual_worker, "model_profile_sha256": pin["model_profile_sha256"],
             "profile": conditional.PROFILE, "projection": conditional.PROJECTION,
             "feature_format": conditional.FEATURE_FORMAT,
             "tensor_sha256": bundle["trainable_tensors_sha256"], "source_sha256": SOURCE_SHA256,
             "quality": "development_only"}
    return ModelBackend(torch, tokenizer, model, trainer, conditional), ready


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise WorkerFault("startup_refused")


def main():
    # Keep original pipe handles, then suppress library/native stdout and stderr.
    # Only framed replies and fixed fatal codes can reach the host.
    output = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    errors = os.fdopen(os.dup(sys.stderr.fileno()), "wb", buffering=0)
    if os.name == "nt":
        import msvcrt
        for descriptor in (sys.stdin.fileno(), output.fileno(), errors.fileno()):
            msvcrt.setmode(descriptor, os.O_BINARY)
    with open(os.devnull, "wb") as quiet:
        os.dup2(quiet.fileno(), sys.stdout.fileno())
        os.dup2(quiet.fileno(), sys.stderr.fileno())
        parser = QuietParser(description=__doc__, add_help=False)
        for name in ("corpus", "model-lock", "output-root"):
            parser.add_argument("--" + name, type=Path, required=True)
        for name in ("run-name", "bundle-sha256", "config-sha256", "worker-sha256"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--startup-timeout-micros", type=int, required=True)
        phase = "startup_refused"
        try:
            args = parser.parse_args()
            backend, ready = admit(args)
            write_frame(output, ready)
            phase = "protocol_refused"
            return serve(sys.stdin.buffer, output, backend, args.config_sha256)
        except BaseException as error:
            code = error.code if isinstance(error, WorkerFault) else phase
            errors.write(("kev_worker:" + code + "\n").encode("ascii"))
            return 2
        finally:
            output.close()
            errors.close()


if __name__ == "__main__":
    raise SystemExit(main())
