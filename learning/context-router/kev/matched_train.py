"""Finite per-base or paired-balanced public runs from the pinned upstream Kev."""
from __future__ import annotations

import argparse
import datetime
import gc
import json
import math
import random
import time
import uuid
from pathlib import Path

import conditional
import matched
import matched_bundle as bundles
import paired
import trainer as frozen
from corpus import checked_root, require, sha_file

MAX_STEPS = 64
MAX_SECONDS = 1800
TOOL_FILES = bundles.TOOL_FILES


def installed_directory():
    directory = Path(__file__).resolve().parent
    require(directory == Path(matched.__file__).resolve().parent == Path(bundles.__file__).resolve().parent
            == Path(paired.__file__).resolve().parent
            == Path(frozen.__file__).resolve().parent, "one installed matched tool directory required")
    return directory


def provenance(lock):
    """Re-use fixed upstream/file/package admission, add exact new source pins."""
    directory = installed_directory()
    matched.validate_shared_sources()
    paths, pin = frozen.provenance(lock, conditional.PROFILE)
    sources = {}
    for name in sorted(TOOL_FILES):
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.resolve() == path and path.stat().st_size <= 1 << 20,
                "direct bounded matched tool source required")
        sources[name] = sha_file(path, 1 << 20)
    require(all(sources[name] == expected for name, expected in matched.SHARED_SOURCES.items()),
            "frozen matched dependencies differ")
    return paths, dict(pin, tool_sources_sha256=sources)


def verify_provenance(profile, current):
    require(type(profile["provenance"]) is dict and profile["provenance"] == current
            and set(current["tool_sources_sha256"]) == TOOL_FILES,
            "matched saved source/model/package provenance differs")


def groups(examples, encoded):
    require(len(examples) == len(encoded), "whole encoded population differs")
    train = [(example, value) for example, value in zip(examples, encoded) if example.partition == "train"]
    dev = [(example, value) for example, value in zip(examples, encoded) if example.partition == "validation"]
    require(len(train) == len(dev) == 32 and len(examples) == 64, "fixed 32/32 supervised matched bases required")
    return train, dev


def gradient_gate(torch, model):
    gradients = [(name, parameter.grad) for name, parameter in model.named_parameters() if parameter.grad is not None]
    require(gradients and all(bool(torch.isfinite(value).all()) for _, value in gradients), "missing/nonfinite matched gradients")
    require(any("lora_" in name and bool(torch.count_nonzero(value)) for name, value in gradients)
            and any(name.startswith("head.") and bool(torch.count_nonzero(value)) for name, value in gradients),
            "nonzero finite LoRA and head gradients required")
    return len(gradients)


def backward_row(torch, model, encoded, label, divisor, started, weight=1.0):
    frozen.clock_check(started)
    scores = model(encoded)
    require(len(scores) == 1 and scores[0].shape == (2,), "single binary utility shape differs")
    logit = scores[0][0] - scores[0][1]
    require(bool(torch.isfinite(logit)), "nonfinite matched utility logit")
    require(type(divisor) is int and divisor > 0 and math.isfinite(weight) and weight > 0,
            "fixed finite original-base loss scaling required")
    raw = torch.nn.functional.binary_cross_entropy_with_logits(
        logit, torch.tensor(label, dtype=torch.float32, device=logit.device))
    loss = raw / divisor if weight == 1.0 else raw * weight / divisor
    require(bool(torch.isfinite(loss)), "nonfinite independent masked BCE")
    loss.backward()
    frozen.clock_check(started)
    return float(loss.detach())


def resource_preflight(torch, model, train, initial_digest, started):
    """Largest known row does one backward and zero optimizer updates."""
    rows = [(len(encoded["ids"]), example.association, slot, example.labels[slot], encoded)
            for example, enc in train for slot, encoded in enumerate(enc) if example.known[slot]]
    require(rows and max(row[0] for row in rows) <= matched.LIMITS["row_tokens"], "largest known row admission")
    size, association, slot, label, encoded = max(rows, key=lambda row: (row[0], row[1], row[2]))
    free, total = torch.cuda.mem_get_info()
    torch.cuda.reset_peak_memory_stats()
    model.train()
    model.head.temperature = 1.0
    model.zero_grad(set_to_none=True)
    loss = backward_row(torch, model, encoded, label, 1, started)
    count = gradient_gate(torch, model)
    peak = torch.cuda.max_memory_allocated()
    model.zero_grad(set_to_none=True)
    require(all(parameter.grad is None for parameter in model.parameters()), "resource gradients not cleared")
    require(frozen.tensor_digest(torch, frozen.trainable_snapshot(model)) == initial_digest,
            "resource admission must not update trainable tensors")
    gc.collect()
    torch.cuda.empty_cache()
    return {"status": "largest-known-row-finite-forward-backward", "association": association,
            "question_slot": slot, "total_row_tokens": size, "bce": loss,
            "finite_gradient_tensors": count, "peak_allocated_bytes": peak,
            "free_vram_before_gate": free, "total_vram": total, "optimizer_updates": 0,
            "gradients_cleared": True, "other_processes_modified": False}


def macro_details(metrics, examples):
    result = dict(metrics)
    result["declared_family_macro"] = {"families": len(metrics["by_declared_family"])}
    result["authored_history_macro"] = dict(metrics["authored_history_macro"],
                                           histories=len(metrics["by_authored_history"]))
    for label, rows in (("declared_family_macro", metrics["by_declared_family"]),
                        ("authored_history_macro", metrics["by_authored_history"])):
        for field in ("bce", "brier", "positive_recall", "negative_specificity"):
            available = [value[field] for value in rows.values() if value[field] is not None]
            result[label][field] = None if not available else sum(available) / len(available)
            result[label][field + "_strata"] = len(available)
    dev = [example for example in examples if example.partition == "validation"]
    result["masked_callbacks"] = sum(not known for example in dev for known in example.known)
    result["multi_positive_bases"] = sum(sum(known and label == 1.0 for known, label in
        zip(example.known, example.labels)) > 1 for example in dev)
    result["known_candidate_callbacks"] = sum(known and kind == "candidate" for example in dev
        for known, kind in zip(example.known, example.kinds))
    result["known_bundle_callbacks"] = sum(known and kind == "bundle" for example in dev
        for known, kind in zip(example.known, example.kinds))
    return result


def evaluate(torch, model, dev, examples, intake, started):
    model.eval()
    logits = {}
    with torch.no_grad():
        for example, encoded in dev:
            frozen.clock_check(started)
            logits[example.association] = frozen.utility_logits(torch, model, encoded, started).cpu().tolist()
    metrics = macro_details(matched.development_metrics(examples, intake, logits), examples)
    return {"metrics": metrics, "utility_logits": logits, "examples": len(dev), "threshold_fitted": False}


def controls(examples, intake):
    dev = [example for example in examples if example.partition == "validation"]
    result = {}
    for name, value in (("constant_probability_half", 0.0), ("select_all", 3.0), ("select_none", -3.0)):
        logits = {example.association: [value] * len(example.known) for example in dev}
        result[name] = macro_details(matched.development_metrics(examples, intake, logits), examples)
        require(result[name]["coverage_surrogate_gates_passed"] is False, "constant control unexpectedly passes")
    return result


def selected_contract(args, saved_profile=None):
    """No flag keeps per-base training; verification infers the saved identity."""
    declared = saved_profile if saved_profile is not None else (
        paired.PROFILE if args.optimization == "paired-balanced" else matched.PROFILE)
    bundle_format, steps = bundles.model_contract(declared)
    mode = "paired-balanced" if declared == paired.PROFILE else "per-base"
    require(args.optimization is None or args.optimization == mode,
            "requested optimization differs from the declared training profile")
    require(args.profile is None or args.profile == declared,
            "requested training profile differs from the optimization contract")
    return declared, bundle_format, steps, mode


def run(args):
    installed_directory()
    model_profile, bundle_format, expected_steps, mode = selected_contract(args)
    require(math.isfinite(args.lr) and 0 < args.lr <= 1e-4 and 0 <= args.seed < 2**32,
            "finite matched learning rate and bounded seed required")
    examples, intake = matched.load_examples(args.corpus, args.seed)
    require(intake["partitions"] == {"train": 32, "validation": 32}, "actual 32/32 matched population required")
    baseline_controls = controls(examples, intake)  # Pure, before model/optimizer construction.
    plan = paired.planning(examples, intake) if mode == "paired-balanced" else None
    pairs = paired.training_pairs(examples, intake) if plan is not None else None
    prior_controls = paired.pure_prior_controls(examples, intake, plan) if plan is not None else None
    paths, pin = provenance(args.model_lock)
    output_root = checked_root(args.output_root)
    output = frozen.run_path(output_root, args.run_name)
    require(not output.exists(), "new matched output required; overwrite is forbidden")
    staging = output_root / (output.name + ".partial-" + uuid.uuid4().hex)
    staging.mkdir()
    profile = {**intake, "provenance": pin, "seed": args.seed, "epochs": 1, "lr": args.lr,
               "weight_decay": 0.01, "max_grad_norm": 1.0, "max_seconds": MAX_SECONDS,
               "max_optimizer_steps": MAX_STEPS, "objective": "independent yes-minus-no masked BCE",
               "warm_start": "pinned-upstream-adapter-and-head", "no_training_permission_from_hashes": True}
    if plan is not None:
        profile.update(training_profile=model_profile, optimization=plan, objective=paired.OBJECTIVE)
    bundles.validate_profile(profile, expected_steps, model_profile=model_profile)
    frozen.save_file(staging / "run-intent.json", profile)
    started = time.monotonic()
    torch, tok, model, _, warm_tensors = frozen.load_model(args.seed, paths)
    # Full packed groups and every complete single row, including masked rows,
    # are admitted strictly before creating an optimizer or applying any update.
    encoded = frozen.encode_all(model, tok, examples, matched.LIMITS)
    train, dev = groups(examples, encoded)
    if pairs is None:
        updates = [[item] for item in train]
        weights = {0.0: 1.0, 1.0: 1.0}
    else:
        updates = [[(examples[index], encoded[index]) for index in pair] for pair in pairs]
        weights = {label: plan["class_weights"][name]["numerator"] / plan["class_weights"][name]["denominator"]
                   for label, name in ((1.0, "positive"), (0.0, "negative"))}
        require(len(updates) == 16 and all(len(unit) == 2 and all(example.partition == "train"
                for example, _ in unit) for unit in updates), "sixteen whole TRAIN pairs required")
    require(len(updates) == expected_steps <= MAX_STEPS, "predeclared update population differs")
    frozen.clock_check(started)
    initial = frozen.trainable_snapshot(model)
    initial_digest = frozen.tensor_digest(torch, initial)
    preflight = resource_preflight(torch, model, train, initial_digest, started)
    print(json.dumps({"resource_preflight": preflight}), flush=True)
    before = evaluate(torch, model, dev, examples, intake, started)
    parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    require(parameters and any("lora_" in name and parameter.requires_grad for name, parameter in model.named_parameters()),
            "actual LoRA trainability required")
    optimizer = torch.optim.AdamW(parameters, lr=args.lr, weight_decay=0.01)
    order = list(range(len(updates)))
    random.Random(args.seed).shuffle(order)
    steps, losses = 0, []
    torch.cuda.reset_peak_memory_stats()
    for index in order:
        frozen.clock_check(started)
        require(steps < MAX_STEPS, "matched optimizer step ceiling")
        model.train()
        model.head.temperature = 1.0
        optimizer.zero_grad(set_to_none=True)
        unit = updates[index]
        known_counts = [sum(example.known) for example, _ in unit]
        require(all(known_counts), "whole supervised bases must contain known labels")
        loss = 0.0
        for (example, enc), known_count in zip(unit, known_counts):
            for row, label, known in zip(enc, example.labels, example.known):
                if known:
                    # Each original base keeps its own known-count denominator.
                    # Paired updates average both bases before one optimizer step.
                    loss += backward_row(torch, model, row, label, known_count * len(unit), started, weights[label])
        gradient_gate(torch, model)
        norm = torch.nn.utils.clip_grad_norm_(parameters, 1.0, error_if_nonfinite=True)
        optimizer.step()
        frozen.clock_check(started)
        require(all(bool(torch.isfinite(parameter).all()) for parameter in parameters), "nonfinite matched optimizer update")
        steps += 1
        losses.append(loss)
        progress = {"optimizer_steps": steps, "known_labels": sum(known_counts), "gradient_norm": float(norm)}
        progress.update({"bce": loss} if plan is None else
                        {"bases_in_update": len(unit), "optimization_loss": loss})
        print(json.dumps(progress), flush=True)
    after = frozen.trainable_snapshot(model)
    changed = [name for name in initial if not torch.equal(initial[name], after[name])]
    require(steps == len(updates) == expected_steps and changed and any("lora_" in name for name in changed)
            and any(name.startswith("head.") for name in changed), "actual finite LoRA and head update required")
    after_digest = frozen.tensor_digest(torch, after)
    after_development = evaluate(torch, model, dev, examples, intake, started)
    raw_gate = after_development["metrics"]["coverage_surrogate_gates_passed"]
    prior_gate = None if prior_controls is None else paired.beats_prior_controls(after_development["metrics"], prior_controls)
    report = {"format": bundle_format, "profile": model_profile, "data_profile": matched.PROFILE,
              "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "matched-public-coverage-surrogate-development", "optimizer_steps": steps,
              "before_trainable_digest": initial_digest, "after_trainable_digest": after_digest,
              "changed_trainable_tensors": len(changed), "warm_start_tensors": warm_tensors,
              "training_losses": losses, "resource_preflight": preflight,
              "before_development": before, "after_development": after_development,
              "constant_controls": baseline_controls, "gpu": torch.cuda.get_device_name(),
              "peak_allocated_bytes": max(preflight["peak_allocated_bytes"], torch.cuda.max_memory_allocated()),
              "elapsed_seconds": time.monotonic() - started, "latency_benchmark": False,
              "test_examples_evaluated": 0, "quarantined_examples_used": 0,
              "useful_model_claim": False, "calibration_fit": False, "threshold_fitted": False,
              "coverage_surrogate_gates_passed": raw_gate and prior_gate is not False}
    if plan is not None:
        report.update(optimization=plan, train_prior_controls=prior_controls,
                      unweighted_coverage_surrogate_gates_passed=raw_gate,
                      train_prior_controls_beaten=prior_gate,
                      utility_score="uncalibrated-discrimination-score",
                      utility_is_calibrated_probability=False)
    reference_example, reference_encoded = dev[0]
    model.eval()
    with torch.no_grad():
        reference = frozen.utility_logits(torch, model, reference_encoded, started).cpu()
    (staging / "run-intent.json").rename(staging / "intent.json")
    bundles.write_bundle(torch, model, optimizer, staging, profile, report, paths["adapter"], model_profile=model_profile)
    del optimizer, parameters, initial, after, model
    gc.collect()
    torch.cuda.empty_cache()
    _, cold_tok, cold, _, _ = frozen.load_model(args.seed, paths)
    bundles.reload_bundle(torch, cold, staging, output_root, model_profile=model_profile)
    cold.eval()
    with torch.no_grad():
        cold_encoded = frozen.encode_all(cold, cold_tok, [reference_example], matched.LIMITS)[0]
        actual = frozen.utility_logits(torch, cold, cold_encoded, started).cpu()
    require(torch.equal(reference, actual), "same-runtime matched cold logits differ")
    frozen.save_file(staging / "cold-reload.json", {"format": bundle_format, "profile": model_profile,
        "data_profile": matched.PROFILE,
        "status": "strict-tensor-and-logit-match", "examples": 1, "from_partition": "validation",
        "association": reference_example.association, "utility_logits": reference.tolist(), "test_evaluated": 0})
    frozen.save_file(staging / "complete.json", {"format": bundle_format, "profile": model_profile,
        "data_profile": matched.PROFILE,
        "bundle_sha256": sha_file(staging / "bundle.json", 64 << 10),
        "cold_reload_sha256": sha_file(staging / "cold-reload.json", 64 << 10), "optimizer_steps": steps})
    bundles.inspect_bundle(staging, output_root, completed=True, model_profile=model_profile)
    frozen.clock_check(started)
    frozen.publish_bundle(staging, output)
    print(json.dumps({"status": "complete-matched-development-bundle", "path": str(output), "optimizer_steps": steps,
                      "profile": model_profile, "data_profile": matched.PROFILE,
                      "coverage_surrogate_gates_passed": report["coverage_surrogate_gates_passed"],
                      "useful_model_claim": False, "test_evaluated": 0}), flush=True)


def verify(args):
    installed_directory()
    root = checked_root(args.output_root)
    path = frozen.run_path(root, args.run_name)
    bundle, profile = bundles.inspect_bundle(path, root, completed=True)
    model_profile, _, _, _ = selected_contract(args, bundle["profile"])
    paths, pin = provenance(args.model_lock)
    verify_provenance(profile, pin)
    examples, intake = matched.load_examples(args.corpus, profile["seed"])
    require(profile["group_metadata"] == intake["group_metadata"], "exact current matched correspondence required")
    if model_profile == paired.PROFILE:
        require(profile["optimization"] == paired.planning(examples, intake), "current TRAIN optimization plan differs")
    reference = bundles.cold_reference(path, model_profile=model_profile)
    example = next((item for item in examples if item.association == reference["association"]
                    and item.partition == "validation"), None)
    require(example is not None and len(reference["utility_logits"]) == len(example.known),
            "cold reference must name one existing matched development base")
    started = time.monotonic()
    torch, tok, model, _, _ = frozen.load_model(profile["seed"], paths)
    bundles.reload_bundle(torch, model, path, root, model_profile=model_profile)
    model.eval()
    with torch.no_grad():
        encoded = frozen.encode_all(model, tok, [example], matched.LIMITS)[0]
        actual = frozen.utility_logits(torch, model, encoded, started).cpu()
    expected = torch.tensor(reference["utility_logits"], dtype=actual.dtype)
    require(torch.equal(actual, expected), "fresh-process matched cold logits differ")
    print(json.dumps({"status": "fresh-process-strict-matched-bundle-and-logit-match",
                      "profile": model_profile, "data_profile": matched.PROFILE,
                      "development_examples": 1, "test_evaluated": 0, "useful_model_claim": False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "train", "verify-bundle"):
        command = sub.add_parser(name)
        command.add_argument("--profile", choices=(matched.PROFILE, paired.PROFILE), default=None)
        command.add_argument("--optimization", choices=("per-base", "paired-balanced"), default=None,
                             help="default per-base; verify-bundle infers the saved training profile")
        command.add_argument("--corpus", type=Path, required=True)
        command.add_argument("--model-lock", type=Path, required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name != "preflight":
            command.add_argument("--run-name", required=True)
        if name == "train":
            command.add_argument("--lr", type=float, default=1e-5)
            command.add_argument("--seed", type=int, default=20261012)
    args = parser.parse_args()
    installed_directory()
    checked_root(args.output_root)
    if args.command == "train":
        run(args)
    elif args.command == "verify-bundle":
        verify(args)
    else:
        model_profile, bundle_format, steps, mode = selected_contract(args)
        examples, intake = matched.load_examples(args.corpus)
        plan = paired.planning(examples, intake) if mode == "paired-balanced" else None
        prior_controls = paired.pure_prior_controls(examples, intake, plan) if plan is not None else None
        _, pin = provenance(args.model_lock)
        print(json.dumps({"status": "matched-preflight-no-model", "examples": len(examples), "intake": intake,
                          "training_profile": model_profile, "bundle_format": bundle_format,
                          "planned_optimizer_steps": steps, "optimization": plan,
                          "train_prior_controls": prior_controls,
                          "source_revision": pin["source_revision"], "tool_sources_sha256": pin["tool_sources_sha256"]}))


if __name__ == "__main__":
    main()
