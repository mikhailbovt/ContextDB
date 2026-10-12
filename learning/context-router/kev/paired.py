"""Pure input-paired training plan over the unchanged fixed matched-v2 corpus."""
from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from fractions import Fraction

import matched
from corpus import canonical, require

PROFILE = "contextdb.kev-public-matched-paired-balanced-lossless-bce.v3"
TRAINING_PROFILE = PROFILE
BUNDLE_FORMAT = "contextdb.kev-matched-paired-balanced-development-bundle.v3"
PLAN_FORMAT = "contextdb.kev-paired-balanced-optimization-plan.v3"
OBJECTIVE = "paired class-balanced independent yes-minus-no masked BCE"
CLASS_WEIGHTS = {"positive": {"numerator": 480, "denominator": 257},
                 "negative": {"numerator": 480, "denominator": 703}}
PRIORS = {"callback_micro": {"numerator": 33, "denominator": 122},
          "per_base_group_mean": {"numerator": 257, "denominator": 960}}
MASKS = {"known_positive": 66, "known_negative": 178, "unknown": 12,
         "all_zero_bases": 17, "mixed_bases": 15, "multi_positive_bases": 13}
CONTROL_KEYS = ("TRAIN_callback_micro", "TRAIN_per_base_group_mean")


def _membership(metadata):
    """Choose every pair solely from fixed host metadata and input proposals."""
    pairs = defaultdict(dict)
    for association, item in metadata.items():
        if item["partition"] != "train":
            continue
        require(item["probe"] in {"missing", "resident"}, "TRAIN unsupervised probes are not optimizer bases")
        matched.digest(association)
        matched.v1.integer(item["selection_step"], 1)
        proposals = item["proposals"]
        require(type(proposals) is list and 0 < len(proposals) <= matched.LIMITS["questions"]
                and len(proposals) == len(set(proposals)), "whole input proposal inventory required")
        for proposal in proposals:
            matched.digest(proposal)
        key = item["history"], item["family"], item["selection_step"]
        require(item["probe"] not in pairs[key], "duplicate input-paired base")
        pairs[key][item["probe"]] = association
    require(len(pairs) == 16 and len({key[0] for key in pairs}) == 8, "exact sixteen TRAIN pairs/eight histories required")
    ordered, witnesses = [], []
    for key, pair in pairs.items():
        require(set(pair) == {"missing", "resident"}, "missing whole TRAIN counterfactual base")
        missing, resident = pair["missing"], pair["resident"]
        left, right = metadata[missing]["proposals"], metadata[resident]["proposals"]
        require(set(left) == set(right), "matched input proposal inventories differ")
        witness = {"history": key[0], "family": key[1], "selection_step": key[2],
                   "missing": missing, "resident": resident,
                   "missing_proposals": sorted(left), "resident_proposals": sorted(right)}
        ordered.append((canonical(witness), (missing, resident), witness))
    ordered.sort(key=lambda item: item[0])
    witnesses = [item[2] for item in ordered]
    coverage = {"missing_questions": sum(len(item["missing_proposals"]) for item in witnesses),
                "resident_questions": sum(len(item["resident_proposals"]) for item in witnesses),
                "shared_proposals": sum(len(item["missing_proposals"]) for item in witnesses),
                "all_proposals_preserved": True}
    require(coverage == {"missing_questions": 128, "resident_questions": 128,
                         "shared_proposals": 128, "all_proposals_preserved": True},
            "actual fixed TRAIN proposal coverage differs")
    return [item[1] for item in ordered], hashlib.sha256(canonical(witnesses)).hexdigest(), coverage


def training_pairs(examples, intake):
    """Return original full-population indices; labels never choose membership."""
    matched.validate_data_profile(intake)
    metadata = intake["group_metadata"]
    require(len(examples) == len(metadata) == 64, "exact fixed matched example inventory required")
    by_id = {}
    for index, example in enumerate(examples):
        require(example.association in metadata and example.association not in by_id
                and example.partition == metadata[example.association]["partition"], "example/data association differs")
        record = example.record
        matched.v1.shape(record, {"state", "questions"})
        questions = matched.v1.array(record["questions"], matched.LIMITS["questions"])
        require(questions and [matched._proposal_key(record["state"], question) for question in questions]
                == metadata[example.association]["proposals"], "whole original semantic proposal order differs")
        by_id[example.association] = index
    require(set(by_id) == set(metadata), "missing fixed matched base")
    membership, _, _ = _membership(metadata)
    result = [(by_id[missing], by_id[resident]) for missing, resident in membership]
    indices = [index for pair in result for index in pair]
    require(len(indices) == len(set(indices)) == 32
            and set(indices) == {index for index, example in enumerate(examples) if example.partition == "train"},
            "all thirty-two TRAIN bases must appear exactly once")
    return result


def _fixed_plan(metadata):
    _, commitment, coverage = _membership(metadata)
    return {"format": PLAN_FORMAT, "training_profile": PROFILE, "data_profile": matched.PROFILE,
            "objective": OBJECTIVE, "epochs": 1, "train_bases": 32, "optimizer_pairs": 16, "optimizer_steps": 16,
            "loss_normalization": "mean of two original per-base known-label means",
            "class_weights": {name: dict(value) for name, value in CLASS_WEIGHTS.items()},
            "train_only_priors": {name: dict(value) for name, value in PRIORS.items()},
            "pair_membership_sha256": commitment, "pair_proposal_coverage": coverage, "train_masks": dict(MASKS),
            "quality_gates": dict(matched.QUALITY),
            "prior_control_gate": {"source": "TRAIN_only", "evaluated_on": "validation",
                "controls": list(CONTROL_KEYS), "strictly_better": ["callback_micro.bce", "callback_micro.brier"]},
            "calibrated_utility_probability": False, "dev_threshold_fitted": False}


def planning(examples, intake):
    pairs = training_pairs(examples, intake)  # Complete input-only pairing precedes label access.
    train_indices = [index for pair in pairs for index in pair]
    counts = {key: 0 for key in MASKS}
    mass, total_positive, total_known = Fraction(0), 0, 0
    for index in train_indices:
        example = examples[index]
        require(len(example.labels) == len(example.known) == len(example.record["questions"])
                and all(type(label) is float and label in (0.0, 1.0) for label in example.labels)
                and all(type(known) is bool for known in example.known)
                and all(known or label == 0.0 for label, known in zip(example.labels, example.known)),
                "independent known/unknown TRAIN mask binding differs")
        positive = sum(known and label == 1.0 for label, known in zip(example.labels, example.known))
        known = sum(example.known)
        require(known > 0, "whole supervised TRAIN base required")
        negative = known - positive
        total_positive += positive
        total_known += known
        mass += Fraction(positive, known)
        counts["known_positive"] += positive
        counts["known_negative"] += negative
        counts["unknown"] += len(example.known) - known
        counts["all_zero_bases"] += positive == 0
        counts["mixed_bases"] += positive > 0 and negative > 0
        counts["multi_positive_bases"] += positive > 1
    group_prior, callback_prior = mass / 32, Fraction(total_positive, total_known)
    require(group_prior == Fraction(257, 960) and callback_prior == Fraction(33, 122)
            and counts == MASKS, "actual TRAIN-only masses/masks differ; no Dev-derived replacement")
    positive_weight, negative_weight = Fraction(1, 2) / group_prior, Fraction(1, 2) / (1 - group_prior)
    require(positive_weight == Fraction(480, 257) and negative_weight == Fraction(480, 703),
            "exact TRAIN class balancing differs")
    return _fixed_plan(intake["group_metadata"])


def validate_saved_profile(profile, actual_steps):
    matched.validate_data_profile(profile)
    require(profile.get("training_profile") == PROFILE and type(profile.get("epochs")) is int
            and profile["epochs"] == 1 and type(actual_steps) is int and actual_steps == 16,
            "one paired-v3 epoch requires sixteen actual optimizer updates")
    require(type(profile.get("optimization")) is dict
            and canonical(profile["optimization"]) == canonical(_fixed_plan(profile["group_metadata"])),
            "saved paired objective/membership/weights/control gates differ")


def pure_prior_controls(examples, intake, plan=None):
    actual_plan = planning(examples, intake)
    require(plan is None or type(plan) is dict and canonical(plan) == canonical(actual_plan),
            "fixed actual TRAIN plan required")
    dev = [example for example in examples if example.partition == "validation"]
    controls = {}
    for name, source in zip(CONTROL_KEYS, ("callback_micro", "per_base_group_mean")):
        fraction = actual_plan["train_only_priors"][source]
        probability = fraction["numerator"] / fraction["denominator"]
        logit = math.log(probability / (1 - probability))
        logits = {example.association: [logit] * len(example.known) for example in dev}
        controls[name] = matched.development_metrics(examples, intake, logits)
    return controls


def beats_prior_controls(metrics, controls):
    """Unweighted Dev loss must improve over both predeclared TRAIN constants."""
    require(set(controls) == set(CONTROL_KEYS), "two fixed TRAIN-only controls required")
    current = metrics["callback_micro"]
    require(all(type(current[field]) in {int, float} and math.isfinite(current[field]) for field in ("bce", "brier")),
            "finite unweighted development losses required")
    return all(current[field] < controls[name]["callback_micro"][field]
               for name in CONTROL_KEYS for field in ("bce", "brier"))
