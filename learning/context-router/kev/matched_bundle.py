"""Strict owned matched-v2 diagnostic bundles; no optimizer resumption."""
from __future__ import annotations

import os
from pathlib import Path

import matched
import trainer as frozen
from corpus import checked_root, fixed_entries, read_json, require, sha_file

FILES = dict(frozen.BUNDLE_LIMITS)
MAX_BYTES = frozen.BUNDLE_MAX_BYTES
TOOL_FILES = {"corpus.py", "trainer.py", "check.py", "conditional.py", "lossless.py",
              "matched.py", "matched_bundle.py", "matched_train.py"}
ARCHITECTURE = {"base": "Qwen/Qwen3.5-0.8B-Base", "base_revision": frozen.BASE_REVISION,
                "lora": 16, "head_dim": 256, "option_isolation": False, "special_embeddings": False,
                "backbone_dtype": "bfloat16", "head_dtype": "float32", "temperature": 1.0,
                "utility": "sigmoid(useful_logit - not_useful_logit)"}


def bounded_json(path, maximum):
    require(path.is_file() and not path.is_symlink() and path.resolve() == path
            and 0 < path.stat().st_size <= maximum, "direct bounded bundle metadata required")
    return read_json(path, maximum)


def cold_reference(path):
    value = bounded_json(path / "cold-reload.json", 64 << 10)
    matched.v1.shape(value, {"format", "profile", "status", "examples", "from_partition", "association",
                            "utility_logits", "test_evaluated"})
    require(value["format"] == matched.BUNDLE_FORMAT and value["profile"] == matched.PROFILE
            and value["status"] == "strict-tensor-and-logit-match" and value["examples"] == 1
            and value["from_partition"] == "validation" and value["test_evaluated"] == 0,
            "existing matched development reference required")
    matched.digest(value["association"])
    import math
    require(type(value["utility_logits"]) is list and 0 < len(value["utility_logits"]) <= matched.LIMITS["questions"]
            and all(type(item) in {int, float} and math.isfinite(item) for item in value["utility_logits"]),
            "bounded finite cold matched logits required")
    return value


def verify_tool_sources(profile):
    pin = profile["provenance"]
    matched.v1.shape(pin, {"source_revision", "adapter_revision", "base_revision", "model_profile_sha256",
                           "initial_files", "packages", "python", "tool_sources_sha256"})
    require(type(pin["tool_sources_sha256"]) is dict and set(pin["tool_sources_sha256"]) == TOOL_FILES,
            "exact matched dependency source inventory required")
    matched.digest(pin["model_profile_sha256"])
    directory = Path(__file__).resolve().parent
    require(directory == Path(matched.__file__).resolve().parent == Path(frozen.__file__).resolve().parent,
            "one installed matched bundle source directory required")
    for name, expected in pin["tool_sources_sha256"].items():
        matched.digest(expected)
        source = directory / name
        require(source.is_file() and not source.is_symlink() and source.resolve() == source
                and source.stat().st_size <= 1 << 20 and sha_file(source, 1 << 20) == expected,
                "matched bundle's actual tool source commitment differs")
    require(all(pin["tool_sources_sha256"][name] == expected for name, expected in matched.SHARED_SOURCES.items()),
            "matched bundle frozen dependencies differ")


def inspect_bundle(path, output_root, completed=False):
    """Admit all declared bytes, paths and hashes before any tensor loader."""
    output_root = checked_root(output_root)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink() and path.resolve() == path
            and path.parent == output_root, "exact owned direct bundle child required")
    bundle = bounded_json(path / "bundle.json", 64 << 10)
    matched.v1.shape(bundle, {"format", "profile", "optimizer_steps", "files", "trainable_tensors_sha256",
                             "useful_model_claim", "current_training_grant"})
    require(bundle["format"] == matched.BUNDLE_FORMAT and bundle["profile"] == matched.PROFILE
            and bundle["useful_model_claim"] is False and bundle["current_training_grant"] is False,
            "only matched-v2 diagnostic bundles are supported")
    matched.v1.integer(bundle["optimizer_steps"], 64, 1)
    matched.digest(bundle["trainable_tensors_sha256"])
    require(type(bundle["files"]) is dict and set(bundle["files"]) == set(FILES), "fixed bundle artifact inventory")
    sizes = {}
    for name, item in bundle["files"].items():
        matched.v1.shape(item, {"bytes", "sha256"})
        sizes[name] = matched.v1.integer(item["bytes"], FILES[name], 1)
        matched.digest(item["sha256"])
    require(sum(sizes.values()) <= MAX_BYTES, "joint bundle byte ceiling")
    completion = (path / "complete.json").exists()
    require(not completed or completion, "completed matched bundle required")
    fixed_entries(path, set(FILES) | ({"bundle.json", "cold-reload.json", "complete.json"} if completion else {"bundle.json"}))
    for name, item in bundle["files"].items():
        artifact = path / name
        require(artifact.is_file() and not artifact.is_symlink() and artifact.resolve() == artifact
                and artifact.stat().st_size == item["bytes"] and sha_file(artifact, item["bytes"]) == item["sha256"],
                "matched bundle artifact commitment differs")
    profile = bounded_json(path / "profile.json", FILES["profile.json"])
    matched.validate_saved_profile(profile, bundle["optimizer_steps"])
    verify_tool_sources(profile)
    require(profile["objective"] == "independent yes-minus-no masked BCE"
            and profile["no_training_permission_from_hashes"] is True
            and profile["warm_start"] == "pinned-upstream-adapter-and-head"
            and profile["max_seconds"] == 1800 and profile["max_optimizer_steps"] == 64,
            "matched optimization contract differs")
    import math
    require(type(profile["lr"]) is float and math.isfinite(profile["lr"]) and 0 < profile["lr"] <= 1e-4
            and type(profile["weight_decay"]) is float and profile["weight_decay"] == 0.01
            and type(profile["max_grad_norm"]) is float and profile["max_grad_norm"] == 1.0,
            "bounded saved optimizer settings differ")
    require(bounded_json(path / "intent.json", FILES["intent.json"]) == profile,
            "saved matched intent/profile association differs")
    matched.v1.integer(profile["seed"], (1 << 32) - 1)
    require(profile["provenance"]["source_revision"] == frozen.SOURCE_REVISION
            and profile["provenance"]["adapter_revision"] == frozen.ADAPTER_REVISION
            and profile["provenance"]["base_revision"] == frozen.BASE_REVISION,
            "pinned upstream warm-start revisions differ")
    architecture = bounded_json(path / "architecture.json", FILES["architecture.json"])
    require(architecture == ARCHITECTURE and all(type(architecture[key]) is type(value) for key, value in ARCHITECTURE.items()),
            "matched saved architecture differs")
    report = bounded_json(path / "development.json", FILES["development.json"])
    require(report["format"] == matched.BUNDLE_FORMAT and report["profile"] == matched.PROFILE
            and report["optimizer_steps"] == bundle["optimizer_steps"]
            and report["after_trainable_digest"] == bundle["trainable_tensors_sha256"]
            and report["useful_model_claim"] is False and report["test_examples_evaluated"] == 0
            and report["quarantined_examples_used"] == 0 and report["threshold_fitted"] is False
            and report["resource_preflight"]["optimizer_updates"] == 0,
            "matched development observation differs")
    if completion:
        complete = bounded_json(path / "complete.json", 64 << 10)
        matched.v1.shape(complete, {"format", "profile", "bundle_sha256", "cold_reload_sha256", "optimizer_steps"})
        cold_reference(path)
        require(complete["format"] == matched.BUNDLE_FORMAT and complete["profile"] == matched.PROFILE
                and complete["optimizer_steps"] == bundle["optimizer_steps"]
                and complete["bundle_sha256"] == sha_file(path / "bundle.json", 64 << 10)
                and complete["cold_reload_sha256"] == sha_file(path / "cold-reload.json", 64 << 10),
                "matched completion commitment differs")
    return bundle, profile


def write_bundle(torch, model, optimizer, staging, profile, report, adapter_path):
    from peft import get_peft_model_state_dict
    from safetensors.torch import save_file as save_tensors
    matched.validate_saved_profile(profile, report["optimizer_steps"])
    adapter = {name: value.detach().cpu().contiguous() for name, value in get_peft_model_state_dict(model.lm).items()}
    head = {name: value.detach().cpu().contiguous() for name, value in model.head.state_dict().items()}
    frozen.tensor_digest(torch, adapter)
    frozen.tensor_digest(torch, head)
    config = read_json(adapter_path / "adapter_config.json", 64 << 10)
    config["base_model_name_or_path"] = ARCHITECTURE["base"]
    config["revision"] = frozen.BASE_REVISION
    save_tensors(adapter, str(staging / "adapter.safetensors"))
    save_tensors(head, str(staging / "head.safetensors"))
    frozen.save_file(staging / "adapter_config.json", config)
    frozen.save_file(staging / "architecture.json", dict(ARCHITECTURE))
    frozen.save_file(staging / "profile.json", profile)
    frozen.save_file(staging / "development.json", report)
    state = optimizer.state_dict()
    for values in state["state"].values():
        for value in values.values():
            if isinstance(value, torch.Tensor):
                require(bool(torch.isfinite(value).all()), "nonfinite diagnostic optimizer state")
    with (staging / "optimizer.pt").open("xb") as stream:
        torch.save(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    fixed_entries(staging, set(FILES))
    sizes = {}
    for name, maximum in FILES.items():
        artifact = staging / name
        require(artifact.is_file() and not artifact.is_symlink() and artifact.resolve() == artifact
                and 0 < artifact.stat().st_size <= maximum, "generated matched artifact exceeds fixed ceiling")
        sizes[name] = artifact.stat().st_size
    require(sum(sizes.values()) <= MAX_BYTES, "generated matched bundle exceeds joint ceiling")
    files = {}
    for name, size in sorted(sizes.items()):
        with (staging / name).open("r+b") as stream:
            os.fsync(stream.fileno())
        files[name] = {"bytes": size, "sha256": sha_file(staging / name, size)}
    frozen.save_file(staging / "bundle.json", {"format": matched.BUNDLE_FORMAT, "profile": matched.PROFILE,
        "optimizer_steps": report["optimizer_steps"], "files": files,
        "trainable_tensors_sha256": report["after_trainable_digest"],
        "useful_model_claim": False, "current_training_grant": False})


def reload_bundle(torch, model, path, output_root):
    from peft import get_peft_model_state_dict, set_peft_model_state_dict
    from safetensors.torch import load_file
    bundle, profile = inspect_bundle(path, output_root)
    adapter = load_file(str(path / "adapter.safetensors"), device="cpu")
    head = load_file(str(path / "head.safetensors"), device="cpu")
    expected = get_peft_model_state_dict(model.lm)
    require(set(adapter) == set(expected) and all(adapter[key].shape == expected[key].shape
            and adapter[key].dtype == expected[key].dtype for key in adapter), "matched adapter keys/shapes/dtypes differ")
    expected_head = model.head.state_dict()
    require(set(head) == set(expected_head) and all(head[key].shape == expected_head[key].shape
            and head[key].dtype == expected_head[key].dtype for key in head), "matched head keys/shapes/dtypes differ")
    frozen.tensor_digest(torch, adapter)
    frozen.tensor_digest(torch, head)
    set_peft_model_state_dict(model.lm, adapter)
    model.head.load_state_dict(head, strict=True)
    model.head.temperature = 1.0
    require(frozen.tensor_digest(torch, frozen.trainable_snapshot(model)) == bundle["trainable_tensors_sha256"],
            "strict matched trainable tensor commitment differs")
    return bundle, profile
