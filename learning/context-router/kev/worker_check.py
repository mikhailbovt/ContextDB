"""Three no-model gates for worker framing, shared projection and fault isolation."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import struct
import sys
import tempfile
import time
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).absolute().parent))
import worker

CONFIG = "c" * 64


def check(condition):
    if not condition:
        raise AssertionError("worker gate failed")


def refuses(code, action):
    try:
        action()
    except worker.WorkerFault as error:
        check(error.code == code and str(error) == code)
        return
    raise AssertionError("worker refusal absent")


def request(value, request_id=1, **changes):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    metadata = {"format": worker.FORMAT, "operation": "score", "id": request_id,
                "config_sha256": CONFIG, "input_bytes": len(payload),
                "input_sha256": hashlib.sha256(payload).hexdigest(), "timeout_micros": worker.MAX_TIMEOUT}
    metadata.update(changes)
    encoded = json.dumps(metadata, separators=(",", ":")).encode()
    return struct.pack(">IH", 2 + len(encoded) + len(payload), len(encoded)) + encoded + payload


def replies(data):
    stream, result = io.BytesIO(data), []
    while stream.tell() < len(data):
        size, metadata_size = struct.unpack(">IH", stream.read(6))
        check(size == metadata_size + 2 and size <= worker.MAX_META)
        result.append(json.loads(stream.read(metadata_size)))
    return result


class Probe:
    def __init__(self, result=0.25, error=None):
        self.calls, self.result, self.error = 0, result, error

    def score(self, value, deadline):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def framing_gate():
    backend, output = Probe(), io.BytesIO()
    stream = request({"natural": "UTF-8: привет\n雪"}) + request({"natural": "second"}, 2)
    check(worker.serve(io.BytesIO(stream), output, backend, CONFIG) == 0)
    messages = replies(output.getvalue())
    check(backend.calls == 2 and [m["id"] for m in messages] == [1, 2]
          and all(m["yes_minus_no"] == 0.25 for m in messages))
    check(all(set(m) == {"format", "operation", "id", "config_sha256", "input_sha256",
                         "status", "yes_minus_no"} for m in messages))

    for changes in ({"id": 0}, {"id": 2}, {"id": True}, {"config_sha256": "d" * 64},
                    {"operation": "train"}, {"timeout_micros": 0},
                    {"timeout_micros": worker.MAX_TIMEOUT + 1}, {"unexpected": "source"}):
        probe, sink = Probe(), io.BytesIO()
        refuses("protocol_refused", lambda: worker.serve(io.BytesIO(request({}, **changes)), sink, probe, CONFIG))
        check(probe.calls == 0 and sink.getvalue() == b"")
    refuses("protocol_refused", lambda: worker.read_frame(io.BytesIO(struct.pack(">I", worker.MAX_FRAME + 1))))
    refuses("protocol_refused", lambda: worker.read_frame(io.BytesIO(b"\x00\x00")))
    for malformed in (b'{"id":1,"id":2}', b'{"x":NaN}', b'{"x":1.5}', b'"\xff"',
                      b'"\\ud800"', b"[" * 33 + b"0" + b"]" * 33,
                      json.dumps([0] * 1025).encode()):
        refuses("protocol_refused", lambda: worker.strict_json(malformed, worker.MAX_INPUT))
    check(worker.strict_json(b'{"quoted":"[{]}"}', worker.MAX_INPUT) == {"quoted": "[{]}"})
    frame = worker.read_frame(io.BytesIO(request({"private": "never-log-this"})))
    check("never-log-this" not in repr(frame))


class FakeScores:
    shape = (1,)

    def __getitem__(self, index):
        check(index == 0)
        return SimpleNamespace(item=lambda: 0.25)


class FakeModel:
    def __init__(self, overflow=False):
        self.overflow, self.seen = overflow, []

    def encode(self, tokenizer, record, **limits):
        check(limits == {"max_state": 2048, "max_branch": 4096, "strict": True})
        check(len(record["questions"]) == 1)
        self.seen.append(record)
        return {"state_truncated": False, "ids": range(4097 if self.overflow else 8), "decide_idx": [7]}


def projection_gate(corpus):
    trainer, conditional = worker.pinned_modules()
    examples, _ = conditional.load_examples(corpus)
    check(len(examples) == 48 and all(e.partition in {"train", "validation"} for e in examples))
    lineage = trainer.read_json(corpus / "lineage.json", conditional.LIMITS["file_bytes"])
    admitted_cases = {a["example_id"] for a in lineage["assignments"] if a["partition"] == "train"}
    observations = trainer.read_json(corpus / "observations.json", conditional.LIMITS["file_bytes"])
    admitted_rows = {r["row_id"] for r in observations if r["case_id"] in admitted_cases}
    inputs = trainer.read_json(corpus / "inputs.json", conditional.LIMITS["file_bytes"])
    value = next(r["input"] for r in inputs if r["row_id"] in admitted_rows
                 and any(b["kind"] != "raw_observation" for b in r["input"]["trial"]["blocks"]))
    expected_state, expected_question = conditional.project(value)
    calls = []

    def logits(torch, model, encoded):
        calls.append(encoded)
        return FakeScores()

    proxy = SimpleNamespace(encode_all=trainer.encode_all, utility_logits=logits)
    torch = SimpleNamespace(no_grad=nullcontext)
    model = FakeModel()
    backend = worker.ModelBackend(torch, None, model, proxy, conditional)
    check(backend.score(value, time.monotonic() + 10) == 0.25 and len(calls) == 1)
    check(model.seen[0] == {"state": expected_state, "questions": [expected_question]})
    # SAME exact trainer admission refuses the complete row; no inference occurs.
    calls.clear()
    refuses("token_refused", lambda: worker.ModelBackend(torch, None, FakeModel(True), proxy, conditional)
            .score(value, time.monotonic() + 10))
    check(not calls)
    mutated = copy.deepcopy(value)
    block = next(b for b in mutated["trial"]["blocks"] if b["kind"] != "raw_observation")
    block["representation"]["fields"]["native_record"] = {"id": "do-not-send"}
    calls.clear()
    refuses("projection_refused", lambda: backend.score(mutated, time.monotonic() + 10))
    check(not calls)


def isolation_gate(old_bundle):
    # Failure replies carry only exact correlation and fixed code; invalidate child.
    for result, error, code in ((math.nan, None, "nonfinite_score"),
                                (worker.MAX_LOGIT + 1.0, None, "nonfinite_score"),
                                (0.25, ValueError("private-source-should-never-appear"), "inference_refused"),
                                (0.25, MemoryError("private-source-should-never-appear"), "resource_refused")):
        probe, output = Probe(result, error), io.BytesIO()
        check(worker.serve(io.BytesIO(request({}) + request({}, 2)), output, probe, CONFIG) == 2)
        message = replies(output.getvalue())
        check(probe.calls == 1 and len(message) == 1 and message[0]["status"] == "error"
              and message[0]["code"] == code and "yes_minus_no" not in message[0])
        check(b"private-source" not in output.getvalue())
    expired = worker.read_frame(io.BytesIO(request({})))
    expired.received_at = time.monotonic() - 31
    probe = Probe()
    refuses("deadline_refused", lambda: worker.score_frame(expired, probe))
    check(probe.calls == 0)
    changed_hash = worker.read_frame(io.BytesIO(request({}, input_sha256="e" * 64)))
    refuses("protocol_refused", lambda: worker.score_frame(changed_hash, probe))
    check(probe.calls == 0)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve() / "oversized"
        path.write_bytes(b"xxx")
        refuses("startup_refused", lambda: worker.file_sha256(path, 2))
    trainer, conditional = worker.pinned_modules()
    try:
        trainer.inspect_bundle(old_bundle, old_bundle.parent, completed=True, profile_name=conditional.PROFILE)
    except ValueError:
        pass
    else:
        raise AssertionError("old bundle accepted by conditional worker")
    check("torch" not in sys.modules and "transformers" not in sys.modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--old-bundle", type=Path, required=True)
    args = parser.parse_args()
    framing_gate()
    projection_gate(args.corpus)
    isolation_gate(args.old_bundle)
    print(json.dumps({"status": "worker-pure-gates-pass", "groups": 3, "model_calls": 0}))


if __name__ == "__main__":
    main()
