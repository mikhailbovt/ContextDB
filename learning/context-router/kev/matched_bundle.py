"""Strict owned diagnostic bundles with explicit data/training identities."""
from __future__ import annotations

import os
import hashlib
import importlib.metadata
import math
import sys
from pathlib import Path

import matched
import paired
import trainer as frozen
from corpus import canonical, checked_root, fixed_entries, read_json, require, sha_file

FILES = dict(frozen.BUNDLE_LIMITS)
MAX_BYTES = frozen.BUNDLE_MAX_BYTES
TOOL_FILES = {"corpus.py", "trainer.py", "check.py", "conditional.py", "lossless.py",
              "matched.py", "paired.py", "matched_bundle.py", "matched_train.py"}
CONTROLLED_PROFILE = "contextdb.kev-public-controlled-history-balanced-bce.v4"
CONTROLLED_TOOL_FILES = TOOL_FILES | {"controlled.py", "controlled_training.py"}
ARCHITECTURE = {"base": "Qwen/Qwen3.5-0.8B-Base", "base_revision": frozen.BASE_REVISION,
                "lora": 16, "head_dim": 256, "option_isolation": False, "special_embeddings": False,
                "backbone_dtype": "bfloat16", "head_dtype": "float32", "temperature": 1.0,
                "utility": "sigmoid(useful_logit - not_useful_logit)"}


def bounded_json(path, maximum):
    require(path.is_file() and not path.is_symlink() and path.resolve() == path
            and 0 < path.stat().st_size <= maximum, "direct bounded bundle metadata required")
    return read_json(path, maximum)


def optimization_contract(profile_name):
    """Legacy profiles never import the separate controlled-v4 dependencies."""
    require(type(profile_name) is str, "declared matched training profile required")
    if profile_name == matched.PROFILE:
        return None
    if profile_name == paired.PROFILE:
        return paired
    require(profile_name == CONTROLLED_PROFILE, "unsupported matched training profile")
    import controlled_training
    require(controlled_training.PROFILE == CONTROLLED_PROFILE,
            "controlled training module identity differs")
    return controlled_training


def _data_module(model_profile):
    optimization_contract(model_profile)
    if model_profile == CONTROLLED_PROFILE:
        import controlled
        return controlled
    return matched


def data_profile(model_profile):
    return _data_module(model_profile)


def tool_files(model_profile):
    optimization_contract(model_profile)
    return set(CONTROLLED_TOOL_FILES if model_profile == CONTROLLED_PROFILE else TOOL_FILES)


def model_contract(profile_name):
    """Training identity determines its format and actual update count."""
    contract = optimization_contract(profile_name)
    if contract is None:
        return matched.BUNDLE_FORMAT, 32
    return contract.BUNDLE_FORMAT, 16 if profile_name == paired.PROFILE else 8


def validate_profile(profile, steps, model_profile=None):
    require(type(profile) is dict and type(profile.get("profile")) is str,
            "declared fixed data profile required")
    declared = profile.get("training_profile", profile["profile"])
    bundle_format, actual_steps = model_contract(declared)
    require(profile["profile"] == data_profile(declared).PROFILE, "training/data profile association differs")
    require(model_profile is None or model_profile == declared, "matched training profile association differs")
    require(type(steps) is int and steps == actual_steps, "actual matched optimizer updates differ")
    if declared == matched.PROFILE:
        require("optimization" not in profile, "paired optimization cannot use the per-base profile")
        matched.validate_saved_profile(profile, steps)
    else:
        optimization_contract(declared).validate_saved_profile(profile, steps)
    return declared, bundle_format


def data_contract(value, model_profile):
    # The old per-base envelope did not repeat its same-named data contract.
    require((model_profile == matched.PROFILE and "data_profile" not in value)
            or value.get("data_profile") == data_profile(model_profile).PROFILE,
            "matched envelope data profile differs")


def cold_reference(path, model_profile=None):
    if model_profile is None:
        bundle, _ = inspect_bundle(path, path.parent, completed=True)
        model_profile = bundle["profile"]
    bundle_format, _ = model_contract(model_profile)
    value = bounded_json(path / "cold-reload.json", 64 << 10)
    matched.v1.shape(value, {"format", "profile", "status", "examples", "from_partition", "association",
                            "utility_logits", "test_evaluated"}, {"data_profile"})
    data_contract(value, model_profile)
    require(value["format"] == bundle_format and value["profile"] == model_profile
            and value["status"] == "strict-tensor-and-logit-match" and value["examples"] == 1
            and value["from_partition"] == "validation" and value["test_evaluated"] == 0,
            "existing matched development reference required")
    matched.digest(value["association"])
    require(type(value["utility_logits"]) is list and 0 < len(value["utility_logits"]) <= _data_module(model_profile).LIMITS["questions"]
            and all(type(item) in {int, float} and math.isfinite(item) for item in value["utility_logits"]),
            "bounded finite cold matched logits required")
    return value


def verify_tool_sources(profile):
    declared = profile.get("training_profile", profile["profile"])
    contract = optimization_contract(declared)
    data = _data_module(declared)
    pin = profile["provenance"]
    matched.v1.shape(pin, {"source_revision", "adapter_revision", "base_revision", "model_profile_sha256",
                           "initial_files", "packages", "python", "tool_sources_sha256"})
    require(type(pin["tool_sources_sha256"]) is dict and set(pin["tool_sources_sha256"]) == tool_files(declared),
            "exact matched dependency source inventory required")
    matched.digest(pin["model_profile_sha256"])
    directory = Path(__file__).resolve().parent
    modules = [matched, paired, frozen]
    if declared == CONTROLLED_PROFILE:
        modules.extend((data, contract))
    require(all(directory == Path(module.__file__).resolve().parent for module in modules),
            "one installed matched bundle source directory required")
    for name, expected in pin["tool_sources_sha256"].items():
        matched.digest(expected)
        source = directory / name
        require(source.is_file() and not source.is_symlink() and source.resolve() == source
                and source.stat().st_size <= 1 << 20 and sha_file(source, 1 << 20) == expected,
                "matched bundle's actual tool source commitment differs")
    require(all(pin["tool_sources_sha256"][name] == expected for name, expected in data.SHARED_SOURCES.items()),
            "matched bundle frozen dependencies differ")
    template = bounded_json(directory / "model-lock.example.json", 64 << 10)
    public_lock = {key: value for key, value in template.items() if key != "paths"}
    expected_files = {f"{key}/{name}": item for key, component in template["components"].items()
                      for name, item in component["files"].items()}
    require(pin["model_profile_sha256"] == hashlib.sha256(canonical(public_lock)).hexdigest()
            and pin["initial_files"] == expected_files and pin["packages"] == template["packages"]
            and pin["python"] == sys.version,
            "matched bundle fixed model/package/runtime provenance differs")
    require(all(importlib.metadata.version(name) == version for name, version in pin["packages"].items()),
            "matched bundle runtime package revision differs")


def validate_development(report, profile, steps, declared):
    """Join diagnostic claims internally; hashes do not prove a training run."""
    _, bundle_format = validate_profile(profile, steps, declared)
    data_contract(report, declared)
    require(report["format"] == bundle_format and report["profile"] == declared
            and type(report["optimizer_steps"]) is int and report["optimizer_steps"] == steps
            and report["useful_model_claim"] is False and report["test_examples_evaluated"] == 0
            and report["quarantined_examples_used"] == 0 and report["threshold_fitted"] is False
            and type(report["resource_preflight"]["optimizer_updates"]) is int
            and report["resource_preflight"]["optimizer_updates"] == 0,
            "matched development observation differs")
    if declared == matched.PROFILE:
        return
    if declared == CONTROLLED_PROFILE:
        optimization_contract(declared).validate_development(report, profile, steps)
        return
    require(type(report["optimization"]) is dict
            and canonical(report["optimization"]) == canonical(profile["optimization"])
            and report["utility_score"] == "uncalibrated-discrimination-score"
            and report["utility_is_calibrated_probability"] is False and report["calibration_fit"] is False,
            "paired development optimization or calibration claim differs")
    population = profile["population_audit"]
    strata = population["strata"]["validation"]
    positive, negative = strata["known_positive"], strata["known_negative"]
    metadata = {key: item for key, item in profile["group_metadata"].items() if item["partition"] == "validation"}
    families = {item["family"] for item in metadata.values()}
    histories = {item["history"] for item in metadata.values()}

    def rate(value):
        require(type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1,
                "finite development rate required")
        return value

    def summary(value, positives=None, negatives=None):
        require(type(value) is dict, "development callback summary required")
        count = matched.v1.integer(value["known_callbacks"], positive + negative, 1)
        for field in ("tp", "tn", "fp", "fn"):
            matched.v1.integer(value[field], count)
        p, n = value["tp"] + value["fn"], value["tn"] + value["fp"]
        require(p + n == count and (positives is None or p == positives)
                and (negatives is None or n == negatives), "development known-label populations differ")
        require(type(value["bce"]) in {int, float} and math.isfinite(value["bce"]) and value["bce"] >= 0,
                "finite development BCE required")
        rate(value["brier"])
        if p:
            rate(value["positive_recall"])
        if n:
            rate(value["negative_specificity"])
        require(value["positive_recall"] == (None if not p else value["tp"] / p)
                and value["negative_specificity"] == (None if not n else value["tn"] / n),
                "development recall/specificity differ from confusion counts")

    def metrics(value):
        require(type(value) is dict and value["threshold"] == 0.5 and value["useful_model_claim"] is False
                and value["real_reader_benefit_verified"] is False and value["test_evaluated"] == 0,
                "fixed uncalibrated development metric contract differs")
        summary(value["callback_micro"], positive, negative)
        require(set(value["by_declared_family"]) == families and set(value["by_authored_history"]) == histories
                and value["all_zero_bases"] == strata["all_zero"]
                and value["matched_callback_pairs"] == population["matched_development_known_utility_changes"]
                and value["matched_history_components"] == population["matched_development_utility_change_history_components"],
                "development family, STOP or matched-history population differs")
        for batch in (value["by_declared_family"], value["by_authored_history"]):
            for item in batch.values():
                summary(item)
            require(all(sum(item[field] for item in batch.values()) == value["callback_micro"][field]
                        for field in ("known_callbacks", "tp", "tn", "fp", "fn")),
                    "development macro populations differ from callback micro counts")
        exact_stop = rate(value["exact_stop"])
        matched_rate = rate(value["matched_pair_correctness"])
        rate(value["matched_history_macro"])
        micro = value["callback_micro"]
        expected = {"bce": micro["bce"] < matched.QUALITY["bce_below"],
                    "brier": micro["brier"] < matched.QUALITY["brier_below"],
                    "recall": micro["positive_recall"] >= matched.QUALITY["positive_recall_at_least"],
                    "specificity": micro["negative_specificity"] >= matched.QUALITY["negative_specificity_at_least"],
                    "exact_stop": exact_stop >= matched.QUALITY["exact_stop_at_least"],
                    "matched_pair": matched_rate >= matched.QUALITY["matched_pair_at_least"],
                    "each_declared_family": all(item["positive_recall"] is not None
                        and item["positive_recall"] >= matched.QUALITY["positive_recall_at_least"]
                        and item["negative_specificity"] is not None
                        and item["negative_specificity"] >= matched.QUALITY["negative_specificity_at_least"]
                        for item in value["by_declared_family"].values())}
        require(type(value["gates"]) is dict and set(value["gates"]) == set(expected)
                and all(type(flag) is bool for flag in value["gates"].values())
                and value["gates"] == expected and type(value["coverage_surrogate_gates_passed"]) is bool
                and value["coverage_surrogate_gates_passed"] == all(expected.values()),
                "development success does not follow all fixed gates")

    after = report["after_development"]
    require(after["examples"] == profile["partitions"]["validation"] and after["threshold_fitted"] is False
            and type(after["utility_logits"]) is dict and set(after["utility_logits"]) == set(metadata),
            "complete fixed development logit inventory required")
    for key, values in after["utility_logits"].items():
        require(type(values) is list and len(values) == len(metadata[key]["proposals"])
                and all(type(value) in {int, float} and math.isfinite(value) for value in values),
                "finite complete development logits required")
    raw = after["metrics"]
    metrics(raw)
    require(raw["masked_callbacks"] == strata["unknown"] and raw["multi_positive_bases"] == strata["multi_positive"]
            and raw["known_candidate_callbacks"] + raw["known_bundle_callbacks"] == positive + negative,
            "reported callback masks and candidate/bundle strata differ")
    controls = report["train_prior_controls"]
    require(type(controls) is dict and set(controls) == set(paired.CONTROL_KEYS),
            "two declared TRAIN-only prior controls required")
    for name, prior in zip(paired.CONTROL_KEYS, ("callback_micro", "per_base_group_mean")):
        value = controls[name]
        metrics(value)
        fraction = profile["optimization"]["train_only_priors"][prior]
        probability = fraction["numerator"] / fraction["denominator"]
        expected_bce = -(positive * math.log(probability) + negative * math.log1p(-probability)) / (positive + negative)
        expected_brier = (positive * (1 - probability) ** 2 + negative * probability ** 2) / (positive + negative)
        require(math.isclose(value["callback_micro"]["bce"], expected_bce, rel_tol=1e-12, abs_tol=1e-12)
                and math.isclose(value["callback_micro"]["brier"], expected_brier, rel_tol=1e-12, abs_tol=1e-12)
                and value["callback_micro"]["tp"] == value["callback_micro"]["fp"] == 0,
                "reported prior controls differ from the fixed TRAIN constants")
    raw_gate = raw["coverage_surrogate_gates_passed"]
    prior_gate = paired.beats_prior_controls(raw, controls)
    require(type(report["unweighted_coverage_surrogate_gates_passed"]) is bool
            and report["unweighted_coverage_surrogate_gates_passed"] == raw_gate
            and type(report["train_prior_controls_beaten"]) is bool and report["train_prior_controls_beaten"] == prior_gate
            and type(report["coverage_surrogate_gates_passed"]) is bool
            and report["coverage_surrogate_gates_passed"] == (raw_gate and prior_gate),
            "paired development success must join raw and TRAIN-prior gates")


def inspect_bundle(path, output_root, completed=False, model_profile=None):
    """Admit all declared bytes, paths and hashes before any tensor loader."""
    output_root = checked_root(output_root)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink() and path.resolve() == path
            and path.parent == output_root, "exact owned direct bundle child required")
    bundle = bounded_json(path / "bundle.json", 64 << 10)
    matched.v1.shape(bundle, {"format", "profile", "optimizer_steps", "files", "trainable_tensors_sha256",
                             "useful_model_claim", "current_training_grant"}, {"data_profile"})
    bundle_format, actual_steps = model_contract(bundle["profile"])
    declared = bundle["profile"]
    require(model_profile is None or model_profile == declared, "requested matched training profile differs")
    data_contract(bundle, declared)
    require(bundle["format"] == bundle_format
            and bundle["useful_model_claim"] is False and bundle["current_training_grant"] is False,
            "only declared matched diagnostic bundles are supported")
    require(matched.v1.integer(bundle["optimizer_steps"], 64, 1) == actual_steps,
            "declared matched optimizer updates differ")
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
    validate_profile(profile, bundle["optimizer_steps"], declared)
    verify_tool_sources(profile)
    contract = optimization_contract(declared)
    expected_objective = "independent yes-minus-no masked BCE" if contract is None else contract.OBJECTIVE
    require(profile["objective"] == expected_objective
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
    validate_development(report, profile, bundle["optimizer_steps"], declared)
    require(report["after_trainable_digest"] == bundle["trainable_tensors_sha256"],
            "matched development trainable commitment differs")
    if completion:
        complete = bounded_json(path / "complete.json", 64 << 10)
        matched.v1.shape(complete, {"format", "profile", "bundle_sha256", "cold_reload_sha256", "optimizer_steps"},
                         {"data_profile"})
        data_contract(complete, declared)
        cold_reference(path, declared)
        require(complete["format"] == bundle_format and complete["profile"] == declared
                and complete["optimizer_steps"] == bundle["optimizer_steps"]
                and complete["bundle_sha256"] == sha_file(path / "bundle.json", 64 << 10)
                and complete["cold_reload_sha256"] == sha_file(path / "cold-reload.json", 64 << 10),
                "matched completion commitment differs")
    return bundle, profile


def write_bundle(torch, model, optimizer, staging, profile, report, adapter_path, model_profile=None):
    declared, bundle_format = validate_profile(profile, report["optimizer_steps"], model_profile)
    data_contract(report, declared)
    require(report["profile"] == declared and report["format"] == bundle_format,
            "generated matched development contract differs")
    validate_development(report, profile, report["optimizer_steps"], declared)
    verify_tool_sources(profile)
    from peft import get_peft_model_state_dict
    from safetensors.torch import save_file as save_tensors
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
    frozen.save_file(staging / "bundle.json", {"format": bundle_format, "profile": declared,
        "data_profile": data_profile(declared).PROFILE,
        "optimizer_steps": report["optimizer_steps"], "files": files,
        "trainable_tensors_sha256": report["after_trainable_digest"],
        "useful_model_claim": False, "current_training_grant": False})


def reload_bundle(torch, model, path, output_root, model_profile=None):
    bundle, profile = inspect_bundle(path, output_root, model_profile=model_profile)
    from peft import get_peft_model_state_dict, set_peft_model_state_dict
    from safetensors.torch import load_file
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
