"""Pure fixed-corpus checks for eight v4 history updates and report authority."""
from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import importlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
FORBIDDEN = {"torch", "transformers", "peft", "safetensors", "kev", "tokenizers", "sentencepiece"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refused(operation):
    try:
        operation()
    except ValueError:
        return
    raise ValueError("history contract accepted a forbidden variant")


class NoModelImports:
    def find_spec(self, fullname, path=None, target=None):
        require(fullname.split(".")[0] not in FORBIDDEN, "model/tensor/tokenizer import forbidden in pure checks")
        return None


def load(directory):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and directory.resolve() == directory, "absolute resolved tool directory required")
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure process required")
    sys.meta_path.insert(0, NoModelImports())
    sys.path.insert(0, str(directory))
    modules = [importlib.import_module(name) for name in ("controlled", "controlled_training")]
    require(all(Path(module.__file__).resolve() == directory / (module.__name__ + ".py") for module in modules), "one local contract directory required")
    modules[0].validate_shared_sources()
    return modules


def associations(training, examples, intake):
    return [tuple(examples[index].association for index in unit) for unit in training.training_units(examples, intake)]


def plan_gate(training, examples, intake):
    units = training.training_units(examples, intake)
    plan = training.planning(examples, intake)
    require(len(units) == 8 and all(len(unit) == 3 for unit in units)
            and len({index for unit in units for index in unit}) == 24
            and plan["optimizer_steps"] == 8 and plan["unit_proposal_coverage"]["questions"] == 240,
            "all twenty-four TRAIN bases must enter eight complete history updates")
    train = [examples[index] for unit in units for index in unit]
    positive = sum(mask and label == 1.0 for example in train for label, mask in zip(example.labels, example.known))
    known = sum(sum(example.known) for example in train)
    macro = sum((Fraction(sum(mask and label == 1.0 for label, mask in zip(example.labels, example.known)), sum(example.known))
                 for example in train), Fraction()) / 24
    require(macro == Fraction(67, 240) and Fraction(positive, known) == Fraction(16, 57)
            and plan["train_only_priors"] == {"callback_micro": {"numerator": 16, "denominator": 57},
                "per_base_group_mean": {"numerator": 67, "denominator": 240}}, "macro and micro TRAIN priors must remain distinct")
    masses = {"positive": Fraction(), "negative": Fraction()}
    for example in train:
        for label, mask in zip(example.labels, example.known):
            if mask:
                kind = "positive" if label == 1.0 else "negative"
                weight = plan["class_weights"][kind]
                masses[kind] += Fraction(weight["numerator"], weight["denominator"]) / (3 * sum(example.known))
    require(masses == {"positive": Fraction(4), "negative": Fraction(4)}
            and sum(not mask for example in train for mask in example.known) == 12
            and sum(not any(mask and label == 1.0 for label, mask in zip(example.labels, example.known)) for example in train) == 8
            and sum(sum(mask and label == 1.0 for label, mask in zip(example.labels, example.known)) > 1 for example in train) == 14,
            "unknowns must carry zero mass while all-zero/multiple-positive bases remain admitted")
    return plan


def independence_gate(training, examples, intake, plan):
    original = associations(training, examples, intake)
    changed = [copy.copy(example) for example in examples]
    for example in changed:
        example.labels = [1.0 - label for label in example.labels]
        example.known = [False] * len(example.known)
    require(associations(training, changed, intake) == original, "labels/masks chose history membership or order")
    refused(lambda: training.planning(changed, intake))
    changed = [copy.copy(example) for example in examples]
    for example in changed:
        if example.partition == "validation":
            example.labels, example.known = [1.0] * 10, [False] * 10
    require(training.planning(changed, intake) == plan, "Dev labels/masks influenced TRAIN normalization")
    reordered = list(reversed(examples))
    require(associations(training, reordered, intake) == original and training.planning(reordered, intake) == plan,
            "input container order changed canonical whole-history execution")


def profile_gate(training, intake, plan):
    profile = dict(intake, epochs=1, training_profile=training.PROFILE, optimization=plan, objective=training.OBJECTIVE,
        seed=20261012, lr=1e-5, weight_decay=0.01, max_grad_norm=1.0, max_seconds=1800,
        warm_start="pinned-upstream-adapter-and-head")
    training.validate_saved_profile(profile, 8)
    refused(lambda: training.validate_saved_profile(profile, 24))
    refused(lambda: training.validate_saved_profile(dict(profile, training_profile=intake["profile"]), 8))
    for field in ("class_weights", "unit_membership_sha256", "train_mask_mass_witness"):
        bad = copy.deepcopy(profile)
        if field == "class_weights":
            bad["optimization"][field]["positive"]["denominator"] += 1
        elif field == "train_mask_mass_witness":
            bad["optimization"][field][0]["label_mask_sha256"] = "0" * 64
        else:
            bad["optimization"][field] = "0" * 64
        refused(lambda: training.validate_saved_profile(bad, 8))
    return profile


def report_fixture(data, training, examples, intake, plan, profile):
    """Structural test fixture only; records no hardware or model result."""
    dev = [example for example in examples if example.partition == "validation"]
    logits = {example.association: [0.0] * 10 for example in dev}
    metrics = training.development_details(data.development_metrics(examples, intake, logits), examples)
    controls = training.pure_prior_controls(examples, intake, plan)
    train = next(example for example in examples if example.partition == "train")
    constants = {name: training.development_details(data.development_metrics(examples, intake,
        {example.association: [value] * 10 for example in dev}), examples)
        for name, value in (("constant_probability_half", 0.0), ("select_all", 3.0), ("select_none", -3.0))}
    return {"format": training.BUNDLE_FORMAT, "profile": training.PROFILE, "data_profile": data.PROFILE,
        "optimizer_steps": 8, "optimization": plan, "useful_model_claim": False, "calibration_fit": False,
        "threshold_fitted": False, "utility_score": "uncalibrated-discrimination-score", "utility_is_calibrated_probability": False,
        "test_examples_evaluated": 0, "quarantined_examples_used": 0, "training_losses": [0.693] * 8,
        "token_admission": {"whole_bases": 48, "question_rows": 480, "all_rows_preserved": True,
            "limits": dict(data.LIMITS), "max_state_tokens": 1, "max_complete_row_tokens": 2, "max_packed_base_tokens": 11},
        "resource_preflight": {"status": "largest-known-base-finite-sequential-forward-backward", "association": train.association,
            "whole_question_rows": 10, "known_question_rows": sum(train.known), "optimizer_updates": 0,
            "gradients_cleared": True, "total_row_tokens": 2, "known_total_row_tokens": 2 * sum(train.known),
            "finite_gradient_tensors": 1, "bce": 0.693},
        "before_development": {"examples": 24, "threshold_fitted": False, "utility_logits": logits, "metrics": metrics},
        "after_development": {"examples": 24, "threshold_fitted": False, "utility_logits": logits, "metrics": metrics},
        "train_prior_controls": controls, "constant_controls": constants,
        "unweighted_coverage_surrogate_gates_passed": False, "train_prior_controls_beaten": False,
        "coverage_surrogate_gates_passed": False}


def report_gate(data, training, examples, intake, plan, profile):
    report = report_fixture(data, training, examples, intake, plan, profile)
    training.validate_development(report, profile, 8)
    require(all(not item["coverage_surrogate_gates_passed"] for item in report["train_prior_controls"].values())
            and not training.beats_prior_controls(report["after_development"]["metrics"], report["train_prior_controls"]),
            "constant controls cannot establish contextual utility")
    # Each mutation keeps the report shape plausible but breaks an independent
    # optimization, score, control, mask/resource or success commitment.
    for field in ("prior", "family", "cost", "gate", "logits", "admission", "calibration"):
        bad = copy.deepcopy(report)
        metrics = bad["after_development"]["metrics"]
        if field == "prior":
            bad["train_prior_controls"][training.CONTROL_KEYS[0]]["callback_micro"]["bce"] = 0.9
        elif field == "family":
            next(iter(metrics["by_declared_family"].values()))["fp"] -= 1
        elif field == "cost":
            metrics["history_cardinality_cost_contrasts"][0]["correctness"] = 1.0
        elif field == "gate":
            bad["coverage_surrogate_gates_passed"] = True
        elif field == "logits":
            bad["after_development"]["utility_logits"].pop(next(iter(bad["after_development"]["utility_logits"])))
        elif field == "admission":
            bad["token_admission"]["question_rows"] = 479
        else:
            bad["utility_is_calibrated_probability"] = True
        refused(lambda: training.validate_development(bad, profile, 8))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="absolute fixed controlled-v4 public corpus directory")
    parser.add_argument("--frozen-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    data, training = load(args.frozen_dir)
    examples, intake = data.load_examples(args.corpus)
    plan = plan_gate(training, examples, intake)
    independence_gate(training, examples, intake, plan)
    profile = profile_gate(training, intake, plan)
    report_gate(data, training, examples, intake, plan, profile)
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure check imported a model dependency")
    print(json.dumps({"status": "pass", "groups": 4, "examples": 48, "optimizer_units": 8, "train_bases": 24,
        "scope": "controlled-history-v4-input-membership-train-mass-and-strict-report-contracts",
        "model_calls": 0, "tokenizer_calls": 0, "tensor_loads": 0, "resource_gate_measured": False,
        "model_quality_measured": False}, sort_keys=True))


if __name__ == "__main__":
    main()
