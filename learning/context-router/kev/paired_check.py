"""Pure fixed-corpus checks for paired-v3 plans and diagnostic report contracts."""
from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import importlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
FORBIDDEN = {"torch", "transformers", "peft", "safetensors", "kev"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refused(operation):
    try:
        operation()
    except ValueError:
        return
    raise ValueError("pure contract accepted a forbidden variant")


class NoModelImports:
    def find_spec(self, fullname, path=None, target=None):
        require(fullname.split(".")[0] not in FORBIDDEN, "model/tensor/tokenizer import forbidden in pure checks")
        return None


def load(directory):
    directory = Path(directory)
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and directory.resolve() == directory, "absolute resolved frozen source directory required")
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure process required")
    sys.meta_path.insert(0, NoModelImports())
    sys.path.insert(0, str(directory))
    modules = [importlib.import_module(name) for name in ("matched", "paired", "matched_train", "matched_bundle")]
    require(all(Path(module.__file__).resolve() == directory / (module.__name__ + ".py") for module in modules),
            "single frozen tool source directory required")
    modules[0].validate_shared_sources()
    return modules


def association_pairs(paired, examples, intake):
    return [(examples[left].association, examples[right].association)
            for left, right in paired.training_pairs(examples, intake)]


def plan_gate(paired, examples, intake):
    pairs = paired.training_pairs(examples, intake)
    plan = paired.planning(examples, intake)
    require(len(pairs) == 16 and len({index for pair in pairs for index in pair}) == 32,
            "every TRAIN base must appear exactly once in sixteen pairs")
    require(plan["train_masks"] == {"known_positive": 66, "known_negative": 178, "unknown": 12,
            "all_zero_bases": 17, "mixed_bases": 15, "multi_positive_bases": 13}, "original masked population differs")
    positive_mass = negative_mass = Fraction(0)
    for pair in pairs:
        for index in pair:
            example = examples[index]
            for label, known in zip(example.labels, example.known):
                if known:
                    weight = plan["class_weights"]["positive" if label == 1.0 else "negative"]
                    term = Fraction(weight["numerator"], weight["denominator"]) / (2 * sum(example.known))
                    if label == 1.0:
                        positive_mass += term
                    else:
                        negative_mass += term
    require(positive_mass == negative_mass == 8, "TRAIN-only weighting must balance exact gradient mass")
    return plan


def independence_gate(paired, examples, intake, plan):
    changed = copy.deepcopy(examples)
    for example in changed:
        example.labels = [1.0 - label for label in example.labels]
        example.known = [False] * len(example.known)
    require(association_pairs(paired, changed, intake) == association_pairs(paired, examples, intake),
            "labels or masks chose input pair membership")
    refused(lambda: paired.planning(changed, intake))
    changed = copy.deepcopy(examples)
    for example in changed:
        if example.partition == "validation":
            example.labels = [1.0 - label for label in example.labels]
            example.known = [False] * len(example.known)
    require(paired.planning(changed, intake) == plan, "Dev labels or masks influenced TRAIN weights")
    reordered = list(reversed(examples))
    require(association_pairs(paired, reordered, intake) == association_pairs(paired, examples, intake)
            and paired.planning(reordered, intake) == plan, "input container order influenced the fixed plan")


def contract_gate(matched, paired, trainer, bundles, intake, plan):
    profile = dict(intake, epochs=1, training_profile=paired.PROFILE, optimization=plan)
    bundles.validate_profile(profile, 16, paired.PROFILE)
    refused(lambda: bundles.validate_profile(profile, 32, paired.PROFILE))
    refused(lambda: bundles.validate_profile(profile, 16, matched.PROFILE))
    legacy = dict(intake, epochs=1)
    bundles.validate_profile(legacy, 32, matched.PROFILE)
    refused(lambda: bundles.validate_profile(legacy, 16, paired.PROFILE))
    for field in ("class_weights", "pair_membership_sha256", "quality_gates"):
        bad = copy.deepcopy(profile)
        if field == "class_weights":
            bad["optimization"][field]["positive"]["denominator"] += 1
        elif field == "quality_gates":
            bad["optimization"][field]["threshold"] = 0.1
        else:
            bad["optimization"][field] = "0" * 64
        refused(lambda: bundles.validate_profile(bad, 16, paired.PROFILE))
    require(trainer.selected_contract(argparse.Namespace(optimization=None, profile=None))[2:] == (32, "per-base"),
            "default training contract changed")
    require(trainer.selected_contract(argparse.Namespace(optimization=None, profile=None), paired.PROFILE)[2:]
            == (16, "paired-balanced"), "saved paired identity lost its actual update count")
    refused(lambda: trainer.selected_contract(argparse.Namespace(optimization="paired-balanced", profile=matched.PROFILE)))
    return profile


def report_gate(matched, paired, trainer, bundles, examples, intake, plan, profile):
    controls = paired.pure_prior_controls(examples, intake, plan)
    require(not paired.beats_prior_controls(controls[paired.CONTROL_KEYS[0]], controls)
            and all(not value["coverage_surrogate_gates_passed"] for value in controls.values()),
            "constant TRAIN controls must not become useful-retrieval proof")
    logits = {example.association: [0.0] * len(example.known) for example in examples if example.partition == "validation"}
    metrics = trainer.macro_details(matched.development_metrics(examples, intake, logits), examples)
    report = {"format": paired.BUNDLE_FORMAT, "profile": paired.PROFILE, "data_profile": matched.PROFILE,
              "optimizer_steps": 16, "optimization": plan, "useful_model_claim": False,
              "test_examples_evaluated": 0, "quarantined_examples_used": 0, "threshold_fitted": False,
              "resource_preflight": {"optimizer_updates": 0}, "calibration_fit": False,
              "utility_score": "uncalibrated-discrimination-score", "utility_is_calibrated_probability": False,
              "after_development": {"examples": 32, "threshold_fitted": False, "utility_logits": logits, "metrics": metrics},
              "train_prior_controls": controls, "unweighted_coverage_surrogate_gates_passed": False,
              "train_prior_controls_beaten": False, "coverage_surrogate_gates_passed": False}
    bundles.validate_development(report, profile, 16, paired.PROFILE)
    for field in ("optimization", "calibration", "quality", "prior", "threshold", "confusion", "logits"):
        bad = copy.deepcopy(report)
        if field == "optimization":
            bad[field]["class_weights"]["positive"]["denominator"] += 1
        elif field == "calibration":
            bad["utility_is_calibrated_probability"] = True
        elif field == "quality":
            bad["coverage_surrogate_gates_passed"] = True
        elif field == "prior":
            bad["train_prior_controls"][paired.CONTROL_KEYS[0]]["callback_micro"]["bce"] = 0.99
        elif field == "threshold":
            bad["after_development"]["metrics"]["threshold"] = 0.1
        elif field == "confusion":
            bad["after_development"]["metrics"]["callback_micro"]["tp"] -= 1
        else:
            bad["after_development"]["utility_logits"].pop(next(iter(logits)))
        refused(lambda: bundles.validate_development(bad, profile, 16, paired.PROFILE))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="absolute fixed matched-v2 public corpus directory")
    parser.add_argument("--frozen-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    matched, paired, trainer, bundles = load(args.frozen_dir)
    examples, intake = matched.load_examples(args.corpus)
    snapshot = copy.deepcopy(examples)
    plan = plan_gate(paired, examples, intake)
    independence_gate(paired, examples, intake, plan)
    profile = contract_gate(matched, paired, trainer, bundles, intake, plan)
    report_gate(matched, paired, trainer, bundles, examples, intake, plan, profile)
    require(examples == snapshot, "pure checks altered original records, labels or masks")
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure model-free process required")
    print(json.dumps({"status": "pass", "groups": 4, "examples": 64, "train_pairs": 16,
        "model_calls": 0, "tokenizer_calls": 0, "tensor_loads": 0,
        "scope": "paired-plan-and-constructed-report-contracts", "actual_training_proven": False}, sort_keys=True))


if __name__ == "__main__":
    main()
