"""Bounded public synthetic Kev development trainer; imports load no model."""
from __future__ import annotations

import argparse
import datetime
import gc
import hashlib
import importlib.metadata
import inspect
import json
import math
import os
import random
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from corpus import (CORPUS_BLAKE3, LIMITS, PINS, PROFILE, canonical, checked_root, fixed_entries,
                    load_examples, read_json, require, sha_file)

SOURCE_REVISION = "5e42a7a03f28134853dd3ff77461457e921e5ec1"
ADAPTER_REVISION = "9a45d25eb2ab761841196625383fa1dff0e56c1e"
BASE_REVISION = "dc7cdfe2ee4154fa7e30f5b51ca41bfa40174e68"
MAX_SECONDS = 1800
BUNDLE_FORMAT = "contextdb.kev-synthetic-bce-development-bundle.v1"
BUNDLE_LIMITS = {"adapter.safetensors": 64 << 20, "head.safetensors": 4 << 20,
                 "optimizer.pt": 128 << 20, "adapter_config.json": 64 << 10,
                 "architecture.json": 64 << 10, "profile.json": 256 << 10,
                 "development.json": 1 << 20, "intent.json": 256 << 10}
BUNDLE_MAX_BYTES = 192 << 20
LEGACY_ADAPTER_FILES = {".gitattributes", "adapter_config.json", "adapter_model.safetensors", "head.pt",
                        "provenance.json", "README.md", "result.json", "tokenizer.json",
                        "tokenizer_config.json", "train.log", "training_config.json", "training_metrics.json"}
LEGACY_BASE_FILES = {".gitattributes", "config.json", "LICENSE", "merges.txt",
                     "model.safetensors-00001-of-00001.safetensors", "model.safetensors.index.json",
                     "preprocessor_config.json", "README.md", "tokenizer.json", "tokenizer_config.json",
                     "video_preprocessor_config.json", "vocab.json"}


def bounded_json(path, maximum):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "bounded bundle metadata required")
    return read_json(path, maximum)


def validate_lock(lock):
    """Only operator paths vary; source, files, packages and architecture are fixed."""
    template = read_json(Path(__file__).with_name("model-lock.example.json"), 64 << 10)
    require(type(lock) is dict and set(lock) == set(template), "model lock fields differ")
    require(all(lock[key] == template[key] for key in template if key != "paths"),
            "unsupported model lock; this tool supports one pinned development profile")
    require(type(lock["paths"]) is dict and set(lock["paths"]) == {"source", "adapter", "base"}
            and all(isinstance(path, str) and path for path in lock["paths"].values()),
            "model lock requires three explicit local paths")
    require(template["components"]["source"]["revision"] == SOURCE_REVISION
            and template["components"]["adapter"]["revision"] == ADAPTER_REVISION
            and template["components"]["base"]["revision"] == BASE_REVISION,
            "installed model profile revisions differ")
    return {key: checked_root(path) for key, path in lock["paths"].items()}


def provenance(lock_path):
    require(lock_path.is_absolute() and lock_path.resolve() == lock_path,
            "absolute resolved model lock required")
    lock = read_json(lock_path, 64 << 10)
    paths = validate_lock(lock)
    require((sys.version_info.major, sys.version_info.minor) ==
            (lock["python"]["major"], lock["python"]["minor"]), "Python runtime profile differs")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=paths["source"],
                                     text=True, timeout=10).strip()
    require(actual == SOURCE_REVISION, "upstream revision changed")
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=paths["source"],
                                     text=True, timeout=10).splitlines()
    require(all(line == "?? build/" for line in status), "upstream source changed")
    for component, definition in lock["components"].items():
        # Names, sizes and digests equal the fixed shipped profile before hashing.
        require(len(definition["files"]) <= 16, "model file count exceeds profile")
        for name, expected in definition["files"].items():
            path = paths[component] / name
            require(path.resolve() == path and path.is_file() and not path.is_symlink()
                    and path.stat().st_size == expected["bytes"]
                    and sha_file(path, expected["bytes"]) == expected["sha256"],
                    "pinned model/source file changed")
    packages = {d.metadata["Name"].lower(): d.version for d in importlib.metadata.distributions()}
    require(all(packages.get(name) == version for name, version in lock["packages"].items()),
            "runtime dependency revision changed")
    public_lock = {key: value for key, value in lock.items() if key != "paths"}
    pin = {"source_revision": SOURCE_REVISION, "adapter_revision": ADAPTER_REVISION,
           "base_revision": BASE_REVISION, "model_profile_sha256": hashlib.sha256(canonical(public_lock)).hexdigest(),
           "initial_files": {f"{key}/{name}": item for key, component in lock["components"].items()
                             for name, item in component["files"].items()},
           "packages": lock["packages"], "python": sys.version,
           "tool_sources_sha256": {name: sha_file(Path(__file__).with_name(name), 1 << 20)
                                   for name in ("corpus.py", "trainer.py", "check.py")}}
    return paths, pin


def load_model(seed, paths):
    # No Hub resolution/network fallback. Paths are complete pinned local snapshots.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    source = str(paths["source"])
    if not sys.path or sys.path[0] != source:
        sys.path.insert(0, source)
    import torch
    from kev.checkpoint import Checkpoint
    from kev.model import DecisionModel, load_tokenizer
    import kev.checkpoint
    require(sha_file(Path(inspect.getfile(DecisionModel)), 1 << 20) ==
            sha_file(paths["source"] / "kev/model.py", 1 << 20) and
            sha_file(Path(kev.checkpoint.__file__), 1 << 20) ==
            sha_file(paths["source"] / "kev/checkpoint.py", 1 << 20), "imported model/checkpoint source differs")
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    require(torch.cuda.is_available() and torch.cuda.is_bf16_supported(), "BF16 CUDA required")
    free, _ = torch.cuda.mem_get_info()
    require(free >= 4 << 30, "at least 4 GiB free VRAM required before model construction; other apps remain running")
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    checkpoint = Checkpoint(str(paths["adapter"]))
    meta = checkpoint.meta
    require(meta.base == "Qwen/Qwen3.5-0.8B-Base" and meta.base_revision and
            BASE_REVISION.startswith(meta.base_revision) and not checkpoint.full and
            meta.lora == 16 and meta.head_dim == 256 and not meta.option_isolation and not meta.special_embeddings,
            "unsupported pinned architecture")
    tok = load_tokenizer(str(paths["base"]))
    model = DecisionModel(str(paths["base"]), tok, "cuda", lora=meta.lora, head_dim=meta.head_dim,
                          option_isolation=False, special_embeddings=False, lora_targets="all",
                          dtype=torch.bfloat16, attn="sdpa")
    # The upstream exact key loader avoids warm_start's unrelated suite.fcntl import.
    tensors = checkpoint._load_adapter_into(model.lm)
    require(tensors == 372, "adapter tensor coverage changed")
    model.head.load_state_dict(meta.head, strict=True)
    model.head.temperature = 1.0  # No reuse of upstream softmax calibration.
    model.lm.config.use_cache = False
    return torch, tok, model, meta, tensors


def encode_all(model, tok, examples):
    encoded = []
    for example in examples:
        enc = model.encode(tok, example.record, max_state=LIMITS["state_tokens"],
                           max_branch=LIMITS["row_tokens"], strict=True)
        require(not enc["state_truncated"] and len(enc["ids"]) <= LIMITS["packed_tokens"],
                "token admission exceeded; truncation is forbidden")
        require(len(enc["decide_idx"]) == len(example.known), "question/mask count differs")
        one_question = []
        for question in example.record["questions"]:
            one_question.append(model.encode(tok, {"state": example.record["state"], "questions": [question]},
                                              max_state=LIMITS["state_tokens"],
                                              max_branch=LIMITS["row_tokens"], strict=True))
        encoded.append(one_question)
    return encoded


def utility_logits(torch, model, enc, started=None):
    # Single-question forward bounds live hidden states to one row. No softmax.
    scores = []
    for question in enc:
        if started is not None:
            clock_check(started)
        scores.append(model(question)[0])
        if started is not None:
            clock_check(started)
    require(all(z.shape == (2,) for z in scores), "two-option utility shape differs")
    logits = torch.stack([z[0] - z[1] for z in scores])
    require(bool(torch.isfinite(logits).all()), "nonfinite utility logits")
    return logits


def masked_bce(torch, logits, example):
    known = torch.tensor(example.known, dtype=torch.bool, device=logits.device)
    targets = torch.tensor(example.labels, dtype=torch.float32, device=logits.device)
    require(bool(known.any()), "no supervised labels")
    loss = torch.nn.functional.binary_cross_entropy_with_logits(logits[known], targets[known])
    require(bool(torch.isfinite(loss)), "nonfinite BCE")
    return loss


def clock_check(started):
    require(time.monotonic() - started < MAX_SECONDS, "development wall-time ceiling exceeded")


def evaluate(torch, model, examples, encoded, started):
    model.eval()
    losses, squared, true_positive, false_positive, false_negative = [], [], 0, 0, 0
    known_labels, known_bundle_positive, known_bundle_negative = 0, 0, 0
    records = []
    with torch.no_grad():
        for example, enc in zip(examples, encoded):
            clock_check(started)
            logits = utility_logits(torch, model, enc, started)
            probabilities = logits.sigmoid().cpu().tolist()
            losses.append((float(masked_bce(torch, logits, example)), sum(example.known)))
            records.append({"association": example.association, "probabilities": probabilities})
            for p, y, known, kind in zip(probabilities, example.labels, example.known, example.kinds):
                if not known:
                    continue
                known_labels += 1
                squared.append((p - y) ** 2)
                prediction = p >= 0.5
                true_positive += prediction and y == 1
                false_positive += prediction and y == 0
                false_negative += not prediction and y == 1
                known_bundle_positive += kind == "bundle" and y == 1
                known_bundle_negative += kind == "bundle" and y == 0
    require(known_labels > 0, "development labels absent")
    return {"examples": len(examples), "known_labels": known_labels,
            "bce": sum(value * count for value, count in losses) / known_labels,
            "brier": sum(squared) / known_labels,
            "threshold": 0.5, "threshold_fitted": False,
            "true_positive": true_positive, "false_positive": false_positive,
            "false_negative": false_negative, "known_bundle_positive": known_bundle_positive,
            "known_bundle_negative": known_bundle_negative,
            "claims_generalization": False, "records": records}


def trainable_snapshot(model):
    return {name: p.detach().cpu().clone() for name, p in model.named_parameters() if p.requires_grad}


def tensor_digest(torch, tensors):
    h = hashlib.sha256()
    for name, tensor in sorted(tensors.items()):
        require(bool(torch.isfinite(tensor).all()), "nonfinite saved tensor")
        h.update(canonical({"name": name, "shape": list(tensor.shape), "dtype": str(tensor.dtype)}))
        h.update(tensor.contiguous().view(torch.uint8).numpy().tobytes())
    return h.hexdigest()


def save_file(path, value):
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def save_bundle(torch, model, meta, optimizer, staging, profile, report, adapter_path):
    from peft import get_peft_model_state_dict
    from safetensors.torch import save_file as save_tensors
    tensors = {name: t.detach().cpu().contiguous() for name, t in get_peft_model_state_dict(model.lm).items()}
    head = {name: t.detach().cpu().contiguous() for name, t in model.head.state_dict().items()}
    tensor_digest(torch, tensors)
    tensor_digest(torch, head)
    adapter_config = read_json(adapter_path / "adapter_config.json")
    adapter_config["base_model_name_or_path"] = "Qwen/Qwen3.5-0.8B-Base"
    adapter_config["revision"] = BASE_REVISION
    # No optimizer resumption support in this development profile.
    save_tensors(tensors, str(staging / "adapter.safetensors"))
    save_tensors(head, str(staging / "head.safetensors"))
    save_file(staging / "adapter_config.json", adapter_config)
    save_file(staging / "architecture.json", {"base": meta.base, "base_revision": BASE_REVISION,
              "lora": meta.lora, "head_dim": meta.head_dim, "option_isolation": False,
              "special_embeddings": False, "backbone_dtype": "bfloat16", "head_dtype": "float32",
              "temperature": 1.0, "utility": "sigmoid(useful_logit - not_useful_logit)"})
    save_file(staging / "profile.json", profile)
    save_file(staging / "development.json", report)
    optimizer_state = optimizer.state_dict()
    for state in optimizer_state["state"].values():
        for value in state.values():
            if isinstance(value, torch.Tensor):
                require(bool(torch.isfinite(value).all()), "nonfinite optimizer state")
    with (staging / "optimizer.pt").open("xb") as stream:
        torch.save(optimizer_state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    fixed_entries(staging, set(BUNDLE_LIMITS))
    admitted = {}
    for name, maximum in BUNDLE_LIMITS.items():
        path = staging / name
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum,
                "generated artifact exceeds fixed profile")
        admitted[name] = path.stat().st_size
    require(sum(admitted.values()) <= BUNDLE_MAX_BYTES, "generated bundle exceeds total byte ceiling")
    files = {}
    for name, size in sorted(admitted.items()):
        path = staging / name
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
        files[name] = {"bytes": size, "sha256": sha_file(path, size)}
    save_file(staging / "bundle.json", {"format": BUNDLE_FORMAT, "profile": PROFILE,
              "optimizer_steps": report["optimizer_steps"], "files": files,
              "trainable_tensors_sha256": report["after_trainable_digest"],
              "useful_model_claim": False, "current_training_grant": False})


def inspect_bundle(staging, output_root, completed=False):
    """Bound every path and artifact before hashing or loading tensor payloads."""
    output_root = checked_root(output_root)
    require(staging.is_absolute() and staging.is_dir() and not staging.is_symlink() and
            staging.resolve() == staging and staging.parent == output_root,
            "exact non-symlink owned bundle child required")
    bundle = bounded_json(staging / "bundle.json", 64 << 10)
    require(set(bundle) == {"format", "profile", "optimizer_steps", "files", "trainable_tensors_sha256",
                            "useful_model_claim", "current_training_grant"}
            and bundle["format"] == BUNDLE_FORMAT and bundle["profile"] == PROFILE
            and bundle["useful_model_claim"] is False and bundle["current_training_grant"] is False,
            "bundle profile differs")
    require(type(bundle["files"]) is dict and set(bundle["files"]) == set(BUNDLE_LIMITS),
            "fixed bundle artifact names required")
    require(all(type(v) is dict and set(v) == {"bytes", "sha256"} and type(v["bytes"]) is int
                and 0 < v["bytes"] <= BUNDLE_LIMITS[k]
                and isinstance(v["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", v["sha256"])
                for k, v in bundle["files"].items()) and
            sum(v["bytes"] for v in bundle["files"].values()) <= BUNDLE_MAX_BYTES,
            "bundle declared artifact/sum ceiling exceeded")
    require(type(bundle["optimizer_steps"]) is int and bundle["optimizer_steps"] in {8, 16}
            and isinstance(bundle["trainable_tensors_sha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", bundle["trainable_tensors_sha256"]),
            "invalid optimization/tensor commitment")
    completion = (staging / "complete.json").exists()
    require(not completed or completion, "completed bundle required")
    extras = {"bundle.json", "cold-reload.json", "complete.json"} if completion else {"bundle.json"}
    fixed_entries(staging, set(bundle["files"]) | extras)
    if completion:
        complete = bounded_json(staging / "complete.json", 64 << 10)
        cold_reference(staging)
        require(set(complete) == {"format", "bundle_sha256", "cold_reload_sha256", "optimizer_steps"}
                and complete["format"] == BUNDLE_FORMAT
                and complete["optimizer_steps"] == bundle["optimizer_steps"]
                and complete["bundle_sha256"] == sha_file(staging / "bundle.json", 64 << 10)
                and complete["cold_reload_sha256"] == sha_file(staging / "cold-reload.json", 64 << 10),
                "completion commitment differs")
    for name, item in bundle["files"].items():
        path = staging / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item["bytes"]
                and sha_file(path, item["bytes"]) == item["sha256"], "bundle digest mismatch")
    profile = bounded_json(staging / "profile.json", BUNDLE_LIMITS["profile.json"])
    require(profile["profile"] == PROFILE and profile["corpus_manifest_blake3"] == CORPUS_BLAKE3
            and profile["corpus_files_sha256"] == PINS and profile["limits"] == LIMITS
            and profile["partitions"] == {"train": 8, "validation": 8, "test": 8, "quarantined": 8}
            and profile["excluded_model_examples"] == 16
            and type(profile["seed"]) is int and 0 <= profile["seed"] < 2**32
            and type(profile["epochs"]) is int and profile["epochs"] in {1, 2}
            and profile["epochs"] * 8 == bundle["optimizer_steps"]
            and profile["objective"] == "independent yes-minus-no masked BCE"
            and profile["no_training_permission_from_hashes"] is True,
            "saved synthetic development profile differs")
    pin = profile["provenance"]
    require(pin["source_revision"] == SOURCE_REVISION and pin["adapter_revision"] == ADAPTER_REVISION
            and pin["base_revision"] == BASE_REVISION, "saved model revision differs")
    architecture = bounded_json(staging / "architecture.json", BUNDLE_LIMITS["architecture.json"])
    expected = {"base": "Qwen/Qwen3.5-0.8B-Base", "base_revision": BASE_REVISION,
                "lora": 16, "head_dim": 256, "option_isolation": False, "special_embeddings": False,
                "backbone_dtype": "bfloat16", "head_dtype": "float32", "temperature": 1.0,
                "utility": "sigmoid(useful_logit - not_useful_logit)"}
    require(architecture == expected and all(type(architecture[key]) is type(value) for key, value in expected.items()),
            "saved architecture profile differs")
    return bundle, profile


def cold_reference(path):
    reference = bounded_json(path / "cold-reload.json", 64 << 10)
    require(set(reference) == {"status", "examples", "from_partition", "association", "utility_logits", "test_evaluated"}
            and reference["status"] == "strict-tensor-and-logit-match"
            and reference["examples"] == 1 and reference["from_partition"] == "validation"
            and reference["test_evaluated"] == 0
            and isinstance(reference["association"], str) and len(reference["association"]) <= 256
            and type(reference["utility_logits"]) is list and 0 < len(reference["utility_logits"]) <= LIMITS["questions"]
            and all(type(value) in {int, float} and math.isfinite(value) for value in reference["utility_logits"]),
            "bounded finite cold development observation required")
    return reference


def reload_bundle(torch, model, staging, output_root):
    from peft import get_peft_model_state_dict, set_peft_model_state_dict
    from safetensors.torch import load_file
    bundle, _ = inspect_bundle(staging, output_root)
    adapter = load_file(str(staging / "adapter.safetensors"), device="cpu")
    head = load_file(str(staging / "head.safetensors"), device="cpu")
    expected = get_peft_model_state_dict(model.lm)
    require(set(adapter) == set(expected) and all(adapter[k].shape == expected[k].shape and
            adapter[k].dtype == expected[k].dtype for k in adapter), "adapter keys/shapes/dtypes differ")
    expected_head = model.head.state_dict()
    require(set(head) == set(expected_head) and all(head[k].shape == expected_head[k].shape and
            head[k].dtype == expected_head[k].dtype for k in head), "head keys/shapes/dtypes differ")
    tensor_digest(torch, adapter)
    tensor_digest(torch, head)
    set_peft_model_state_dict(model.lm, adapter)
    model.head.load_state_dict(head, strict=True)
    model.head.temperature = 1.0
    require(tensor_digest(torch, trainable_snapshot(model)) == bundle["trainable_tensors_sha256"],
            "cold-loaded trainable tensor commitment differs")


def run_path(output_root, name):
    reserved = {"con", "prn", "aux", "nul"} | {f"{prefix}{i}" for prefix in ("com", "lpt") for i in range(1, 10)}
    require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
            and name not in reserved, "simple nonreserved run name required")
    return checked_root(output_root) / name


def publish_bundle(staging, output):
    """Atomic directory publication with no replacement on Windows and Linux."""
    require(staging.is_dir() and not staging.is_symlink() and staging.resolve() == staging
            and staging.parent == output.parent and not output.exists(), "new sibling output required")
    if os.name == "nt":
        os.rename(staging, output)  # Windows refuses an existing destination.
    elif sys.platform == "linux":
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        require(hasattr(libc, "renameat2"), "atomic no-replace publication unavailable")
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
            raise OSError(ctypes.get_errno(), "atomic no-replace publication refused")
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        raise ValueError("this development publisher supports Windows and Linux")


def verify_recorded_pin(profile, current):
    """Also accepts the prior development bundle's expanded file manifest."""
    recorded = profile["provenance"]
    require(all(recorded[name] == current[name] for name in
                ("source_revision", "adapter_revision", "base_revision")), "recorded source/model revisions differ")
    require(all(recorded["packages"].get(name) == value for name, value in current["packages"].items()),
            "recorded runtime packages differ")
    files = recorded["initial_files"]
    require(type(files) is dict and len(files) <= 64, "recorded model file inventory exceeds bound")
    if "model_profile_sha256" in recorded:
        require(set(recorded) == {"source_revision", "adapter_revision", "base_revision", "model_profile_sha256",
                                  "initial_files", "packages", "python", "tool_sources_sha256"}
                and files == current["initial_files"] and recorded["packages"] == current["packages"]
                and recorded["model_profile_sha256"] == current["model_profile_sha256"],
                "recorded portable model profile differs")
        return
    # Explicit compatibility with the earlier same-profile public-synthetic run.
    # Extra upstream metadata/logs are never opened or used as executable input.
    require(set(recorded) == {"source_revision", "adapter_revision", "base_revision", "initial_files",
                              "packages", "python", "draft_sources_sha256"}, "unsupported legacy provenance")
    allowed = {"models/kev-0.8b/" + name for name in LEGACY_ADAPTER_FILES}
    allowed |= {"models/qwen3.5-0.8b-base/" + name for name in LEGACY_BASE_FILES}
    require(set(files) == allowed and type(recorded["draft_sources_sha256"]) is dict
            and set(recorded["draft_sources_sha256"]) == {"corpus.py", "trainer.py", "check_draft.py"}
            and all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
                    for value in recorded["draft_sources_sha256"].values()), "legacy provenance inventory differs")
    required_legacy = {}
    for name, expected in current["initial_files"].items():
        component, relative = name.split("/", 1)
        if component != "source":
            prefix = "models/kev-0.8b/" if component == "adapter" else "models/qwen3.5-0.8b-base/"
            required_legacy[prefix + relative] = expected
    require(all(files[name] == expected for name, expected in required_legacy.items()), "recorded warm-start pin differs")
    require(all(type(item) is dict and set(item) == {"bytes", "sha256"} and type(item["bytes"]) is int
                and 0 <= item["bytes"] <= (required_legacy[name]["bytes"] if name in required_legacy else 32 << 20)
                and isinstance(item["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                for name, item in files.items()), "legacy metadata exceeds fixed bounds")


def run(args):
    require(1 <= args.epochs <= 2 and math.isfinite(args.lr) and 0 < args.lr <= 1e-4,
            "development optimization ceiling")
    require(0 <= args.seed < 2**32, "seed exceeds supported range")
    examples, intake = load_examples(args.corpus, args.seed)
    paths, pin = provenance(args.model_lock)
    output_root = checked_root(args.output_root)
    output = run_path(output_root, args.run_name)
    require(not output.exists(), "new output required; overwrite is forbidden")
    staging = output_root / (output.name + ".partial-" + uuid.uuid4().hex)
    staging.mkdir()
    profile = {**intake, "provenance": pin, "seed": args.seed, "epochs": args.epochs,
               "lr": args.lr, "weight_decay": 0.01, "max_grad_norm": 1.0,
               "max_seconds": MAX_SECONDS, "objective": "independent yes-minus-no masked BCE",
               "no_training_permission_from_hashes": True}
    save_file(staging / "run-intent.json", profile)
    started = time.monotonic()
    torch, tok, model, meta, tensors = load_model(args.seed, paths)
    encoded = encode_all(model, tok, examples)
    train = [(x, e) for x, e in zip(examples, encoded) if x.partition == "train"]
    dev = [(x, e) for x, e in zip(examples, encoded) if x.partition == "validation"]
    require(len(train) == len(dev) == 8, "train/dev population differs")
    torch.cuda.reset_peak_memory_stats()
    before_dev = evaluate(torch, model, *zip(*dev), started)
    initial = trainable_snapshot(model)
    initial_digest = tensor_digest(torch, initial)
    parameters = [p for p in model.parameters() if p.requires_grad]
    require(parameters and any("lora_" in n and p.requires_grad for n, p in model.named_parameters()), "LoRA trainability absent")
    optimizer = torch.optim.AdamW(parameters, lr=args.lr, weight_decay=0.01)
    steps, losses = 0, []
    rng = random.Random(args.seed)
    for _ in range(args.epochs):
        order = list(range(len(train)))
        rng.shuffle(order)
        for index in order:
            clock_check(started)
            model.train()
            model.head.temperature = 1.0
            optimizer.zero_grad(set_to_none=True)
            example, enc = train[index]
            known_count = sum(example.known)
            loss_total = 0.0
            for question, y, known in zip(enc, example.labels, example.known):
                if not known:
                    continue
                clock_check(started)
                scores = model(question)
                require(len(scores) == 1 and scores[0].shape == (2,), "binary utility shape differs")
                logits = scores[0][0] - scores[0][1]
                require(bool(torch.isfinite(logits)), "nonfinite training logit")
                loss = torch.nn.functional.binary_cross_entropy_with_logits(
                    logits, torch.tensor(y, dtype=torch.float32, device=logits.device)) / known_count
                require(bool(torch.isfinite(loss)), "nonfinite masked BCE")
                loss.backward()
                clock_check(started)
                loss_total += float(loss.detach())
                del scores, logits, loss
            gradients = [(n, p.grad) for n, p in model.named_parameters() if p.grad is not None]
            require(gradients and all(bool(torch.isfinite(g).all()) for _, g in gradients), "nonfinite/missing gradients")
            require(any("lora_" in n and bool(torch.count_nonzero(g)) for n, g in gradients) and
                    any(n.startswith("head.") and bool(torch.count_nonzero(g)) for n, g in gradients),
                    "LoRA/head gradients must both be nonzero")
            norm = torch.nn.utils.clip_grad_norm_(parameters, 1.0, error_if_nonfinite=True)
            optimizer.step()
            require(all(bool(torch.isfinite(p).all()) for p in parameters), "nonfinite optimizer update")
            steps += 1
            losses.append(loss_total)
            print(json.dumps({"optimizer_steps": steps, "known_labels": sum(example.known),
                              "bce": losses[-1], "gradient_norm": float(norm)}), flush=True)
    after = trainable_snapshot(model)
    changed = [name for name in initial if not torch.equal(initial[name], after[name])]
    require(steps == len(train) * args.epochs and changed and
            any("lora_" in n for n in changed) and any(n.startswith("head.") for n in changed),
            "nonzero accepted LoRA/head update required")
    after_dev = evaluate(torch, model, *zip(*dev), started)
    report = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "synthetic-development-optimization", "optimizer_steps": steps,
              "before_trainable_digest": initial_digest, "after_trainable_digest": tensor_digest(torch, after),
              "changed_trainable_tensors": len(changed), "warm_start_tensors": tensors,
              "training_losses": losses, "before_development": before_dev, "after_development": after_dev,
              "gpu": torch.cuda.get_device_name(), "peak_allocated_bytes": torch.cuda.max_memory_allocated(),
              "elapsed_seconds": time.monotonic() - started, "latency_benchmark": False,
              "test_examples_evaluated": 0, "quarantined_examples_used": 0,
              "useful_model_claim": False, "calibration_fit": False}
    model.eval()
    with torch.no_grad():
        reference = utility_logits(torch, model, dev[0][1], started).cpu()
    # The partial intent is retained on failures; only complete artifacts publish.
    (staging / "run-intent.json").rename(staging / "intent.json")
    save_bundle(torch, model, meta, optimizer, staging, profile, report, paths["adapter"])
    del optimizer, parameters, initial, after, gradients, model
    gc.collect()
    torch.cuda.empty_cache()
    _, tok, cold, _, _ = load_model(args.seed, paths)
    reload_bundle(torch, cold, staging, output_root)
    cold.eval()
    with torch.no_grad():
        cold_logits = utility_logits(torch, cold, encode_all(cold, tok, [dev[0][0]])[0], started).cpu()
    require(torch.equal(reference, cold_logits), "same-runtime cold logits differ")
    save_file(staging / "cold-reload.json", {"status": "strict-tensor-and-logit-match",
              "examples": 1, "from_partition": "validation", "association": dev[0][0].association,
              "utility_logits": reference.tolist(), "test_evaluated": 0})
    # Cold evidence is also committed by a final completion manifest.
    save_file(staging / "complete.json", {"format": BUNDLE_FORMAT, "bundle_sha256": sha_file(staging / "bundle.json"),
              "cold_reload_sha256": sha_file(staging / "cold-reload.json"), "optimizer_steps": steps})
    require(not output.exists(), "output appeared during run")
    clock_check(started)
    publish_bundle(staging, output)
    print(json.dumps({"status": "complete-development-bundle", "path": str(output),
                      "optimizer_steps": steps, "test_evaluated": 0, "useful_model_claim": False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight", help="data/model-file provenance; imports no model")
    training = sub.add_parser("train", help="explicit bounded CUDA development optimization")
    training.add_argument("--epochs", type=int, default=1)
    training.add_argument("--lr", type=float, default=1e-5)
    training.add_argument("--seed", type=int, default=20261009)
    verifying = sub.add_parser("verify-bundle", help="fresh-process strict reload; one existing development example only")
    for command in (preflight, training, verifying):
        command.add_argument("--corpus", type=Path, required=True, help="absolute pinned public replay corpus directory")
        command.add_argument("--model-lock", type=Path, required=True, help="absolute operator model lock JSON")
        command.add_argument("--output-root", type=Path, required=True, help="existing absolute owned output directory")
    for command in (training, verifying):
        command.add_argument("--run-name", required=True, help="direct child name; train never overwrites")
    args = parser.parse_args()
    checked_root(args.output_root)
    if args.command == "preflight":
        examples, intake = load_examples(args.corpus)
        _, pin = provenance(args.model_lock)
        print(json.dumps({"status": "preflight-no-model", "examples": len(examples),
                          "intake": intake, "source_revision": pin["source_revision"],
                          "model_profile_sha256": pin["model_profile_sha256"]}))
    elif args.command == "train":
        run(args)
    else:
        path = run_path(args.output_root, args.run_name)
        _, profile = inspect_bundle(path, args.output_root, completed=True)
        paths, pin = provenance(args.model_lock)
        verify_recorded_pin(profile, pin)
        examples, _ = load_examples(args.corpus, profile["seed"])
        reference = cold_reference(path)
        example = next((e for e in examples if e.association == reference["association"]
                        and e.partition == "validation"), None)
        require(example is not None and len(reference["utility_logits"]) == len(example.known),
                "cold observation must name one existing development row with exact question count")
        started = time.monotonic()
        torch, tok, model, _, _ = load_model(profile["seed"], paths)
        reload_bundle(torch, model, path, args.output_root)
        model.eval()
        with torch.no_grad():
            actual = utility_logits(torch, model, encode_all(model, tok, [example])[0], started).cpu()
        expected = torch.tensor(reference["utility_logits"], dtype=actual.dtype)
        require(torch.equal(actual, expected), "fresh-process development logits differ")
        print(json.dumps({"status": "fresh-process-strict-bundle-and-logit-match", "development_examples": 1,
                          "test_evaluated": 0, "useful_model_claim": False}), flush=True)


if __name__ == "__main__":
    main()
