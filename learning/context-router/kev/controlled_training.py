"""Pure fixed v4 history-triple objective and diagnostic report contracts."""
from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
import hashlib
import math
from types import SimpleNamespace

import controlled
from corpus import canonical, require

PROFILE = "contextdb.kev-public-controlled-history-balanced-bce.v4"
TRAINING_PROFILE = PROFILE
BUNDLE_FORMAT = "contextdb.kev-controlled-history-development-bundle.v4"
PLAN_FORMAT = "contextdb.kev-controlled-history-optimization-plan.v4"
OBJECTIVE = "history-triple class-balanced independent yes-minus-no masked BCE"
CONTROL_KEYS = ("TRAIN_callback_micro", "TRAIN_per_base_group_mean")
SEED, LEARNING_RATE, STEPS = 20261012, 1e-5, 8


def _sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _fraction(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def _membership(metadata):
    histories = defaultdict(list)
    for association, item in metadata.items():
        if item["partition"] == "train":
            controlled.matched.digest(association)
            require(item["selection_step"] == 0 and len(set(item["proposals"])) == 10,
                    "complete fixed TRAIN proposal inventory required")
            histories[item["history"]].append(association)
    require(len(histories) == 8, "eight whole TRAIN histories required")
    units, witnesses = [], []
    for history in sorted(histories):
        members = sorted(histories[history], key=lambda association: canonical([
            metadata[association]["case"], metadata[association]["probe"], sorted(metadata[association]["proposals"]), association]))
        probes = {metadata[association]["probe"] for association in members}
        require(len(members) == 3 and probes in ({"sufficient", "irrelevant", "partial"}, {"sufficient", "stale", "partial"})
                and len({frozenset(metadata[association]["proposals"]) for association in members}) == 1,
                "three original source-corresponding resident bases required")
        units.append(tuple(members))
        witnesses.append({"history": history, "members": [{"association": association,
            "case": metadata[association]["case"], "probe": metadata[association]["probe"],
            "proposals": sorted(metadata[association]["proposals"])} for association in members]})
    require(len({association for unit in units for association in unit}) == 24, "all TRAIN bases appear exactly once")
    coverage = {"histories": 8, "bases": 24, "questions": 240, "per_base_questions": 10,
                "shared_proposals_per_history": 10, "all_proposals_preserved": True}
    return units, _sha(witnesses), coverage


def training_units(examples, intake):
    """Full-population indices; labels/masks/family names never choose order."""
    controlled.validate_data_profile(intake)
    metadata = intake["group_metadata"]
    require(len(examples) == len(metadata) == 48, "all fixed controlled bases required")
    histories, _, _, _ = controlled._seed_assets()
    by_id = {}
    for index, example in enumerate(examples):
        association = example.association
        require(association in metadata and association not in by_id and example.partition == metadata[association]["partition"],
                "controlled example association/fold differs")
        controlled.v1.shape(example.record, {"state", "questions"})
        questions = controlled.v1.array(example.record["questions"], 10)
        require(len(questions) == 10 and questions == sorted(questions, key=canonical), "whole input-only canonical question order required")
        item = metadata[association]
        history = histories[item["history"]]
        original = {source["text"]: source for source in history["originals"] if source["id"] in history["candidate_source_ids"]}
        for question, declared, proposal in zip(questions, item["proposal_sources"], item["proposals"]):
            _, restored = controlled.lossless.expand(example.record["state"], question)
            seeds = [block for block in controlled.lossless._question(restored)["trial"]["blocks"] if block["seed"]]
            require(len(seeds) in {1, 2} and all(len(block["supports"]) == 1 for block in seeds), "whole actual source proposal required")
            sources = []
            for block in seeds:
                source = original[block["supports"][0]["excerpt"]]
                require(block["source_class"] == controlled.ROLES[source["role"]], "original proposal speaker differs")
                sources.append(source["id"])
            require(sorted(sources) == declared and _sha(sorted(sources)) == proposal, "record/proposal-source correspondence differs")
        by_id[association] = index
    require(set(by_id) == set(metadata), "complete fixed controlled association inventory required")
    members, _, _ = _membership(metadata)
    result = [tuple(by_id[association] for association in unit) for unit in members]
    require({index for unit in result for index in unit} == {index for index, example in enumerate(examples) if example.partition == "train"},
            "every original TRAIN base must enter one history update")
    return result


def _source_masks(profile):
    """Derive mask witnesses from fixed source recipes; reconstruct no model record."""
    histories, annotation_path, _, info = controlled._seed_assets()
    recipes = controlled._recipes(annotation_path, histories)
    witnesses = []
    for association, item in sorted(profile["group_metadata"].items(), key=lambda pair: (pair[1]["case"], pair[1]["partition"], pair[0])):
        case = info[item["case"]]
        require(item["history"] == case["history_id"] and item["probe"] == case["probe"], "fixed source-resident association differs")
        recipe = recipes[item["history"]]
        required, selected = set(recipe["sufficient_source_sets"][0]), set(case["resident_source_ids"])
        labels, masks = [], []
        for sources in item["proposal_sources"]:
            trial = selected | set(sources)
            useful = (False if required <= selected or not (required & trial) - selected else
                      None if recipe["rule"] == "sufficient_union_only" and not required <= trial else True)
            labels.append(float(useful is True))
            masks.append(useful is not None)
        witnesses.append(SimpleNamespace(association=association, partition=item["partition"], labels=labels, known=masks,
            kinds=["bundle" if len(sources) == 2 else "candidate" for sources in item["proposal_sources"]]))
    return witnesses


def _statistics(examples, membership):
    by_id = {example.association: example for example in examples}
    counts = {key: 0 for key in ("known_positive", "known_negative", "unknown", "all_zero_bases", "mixed_bases", "multi_positive_bases")}
    positive_mass, total_known, witness = Fraction(), 0, []
    for association in (association for unit in membership for association in unit):
        example = by_id[association]
        require(example.partition == "train" and len(example.labels) == len(example.known) == 10
                and all(type(label) is float and label in (0.0, 1.0) for label in example.labels)
                and all(type(known) is bool for known in example.known)
                and all(known or label == 0.0 for label, known in zip(example.labels, example.known)), "independent TRAIN mask/label binding required")
        positive = sum(known and label == 1.0 for label, known in zip(example.labels, example.known))
        known = sum(example.known)
        require(known > 0, "whole supervised TRAIN base required")
        negative, unknown = known - positive, 10 - known
        positive_mass += Fraction(positive, known)
        total_known += known
        for field, value in (("known_positive", positive), ("known_negative", negative), ("unknown", unknown),
            ("all_zero_bases", positive == 0), ("mixed_bases", positive > 0 and negative > 0), ("multi_positive_bases", positive > 1)):
            counts[field] += value
        witness.append({"association": association, "known_positive": positive, "known_negative": negative, "unknown": unknown,
            "positive_fraction": _fraction(Fraction(positive, known)), "label_mask_sha256": _sha(list(zip(example.labels, example.known)))})
    base_prior, micro_prior = positive_mass / 24, Fraction(counts["known_positive"], total_known)
    require(0 < base_prior < 1 and 0 < micro_prior < 1, "TRAIN-only macro/micro class priors required")
    weights = {"positive": Fraction(1, 2) / base_prior, "negative": Fraction(1, 2) / (1 - base_prior)}
    masses = {"positive": positive_mass * weights["positive"] / 3,
              "negative": (24 - positive_mass) * weights["negative"] / 3}
    require(masses == {"positive": Fraction(4), "negative": Fraction(4)}, "eight history updates must balance exact known class mass")
    return counts, witness, {"callback_micro": micro_prior, "per_base_group_mean": base_prior}, weights, masses


def _fixed_plan(profile):
    membership, commitment, coverage = _membership(profile["group_metadata"])
    counts, witnesses, priors, weights, masses = _statistics(_source_masks(profile), membership)
    observed = profile["population_audit"]["strata"]["train"]
    require(counts == {"known_positive": observed["known_positive"], "known_negative": observed["known_negative"], "unknown": observed["unknown"],
        "all_zero_bases": observed["all_zero"], "mixed_bases": observed["mixed"], "multi_positive_bases": observed["multi_positive"]},
        "fixed source-derived TRAIN mask census differs from admitted data")
    return {"format": PLAN_FORMAT, "training_profile": PROFILE, "data_profile": controlled.PROFILE, "objective": OBJECTIVE,
        "epochs": 1, "train_bases": 24, "optimizer_units": 8, "optimizer_steps": 8, "members_per_unit": 3,
        "loss_normalization": "mean of three original per-base known-label means", "known_row_divisor": "3*K_b",
        "class_weights": {key: _fraction(value) for key, value in weights.items()},
        "train_only_priors": {key: _fraction(value) for key, value in priors.items()}, "train_masks": counts,
        "train_mask_mass_witness": witnesses, "weighted_epoch_class_mass": {key: _fraction(value) for key, value in masses.items()},
        "unit_membership_sha256": commitment, "unit_proposal_coverage": coverage, "training_units": [list(unit) for unit in membership],
        "canonical_unit_order": True, "random_shuffle": False, "seed": SEED, "learning_rate": LEARNING_RATE,
        "weight_decay": 0.01, "gradient_clip": 1.0, "maximum_seconds": 1800, "optimizer_resume": False,
        "quality_gates": dict(controlled.QUALITY), "prior_control_gate": {"source": "TRAIN_only", "evaluated_on": "validation",
            "controls": list(CONTROL_KEYS), "strictly_better": ["callback_micro.bce", "callback_micro.brier"]},
        "calibrated_utility_probability": False, "dev_threshold_fitted": False}


def planning(examples, intake):
    units = training_units(examples, intake)  # Input-only membership is fixed before labels or masks are read.
    membership = [tuple(examples[index].association for index in unit) for unit in units]
    actual = _statistics(examples, membership)
    plan = _fixed_plan(intake)
    require(actual[0] == plan["train_masks"] and actual[1] == plan["train_mask_mass_witness"]
            and {key: _fraction(value) for key, value in actual[2].items()} == plan["train_only_priors"]
            and {key: _fraction(value) for key, value in actual[3].items()} == plan["class_weights"],
            "actual TRAIN-only per-base masks/masses differ from fixed source coverage")
    return plan


def validate_saved_profile(profile, actual_steps):
    controlled.validate_data_profile(profile)
    require(profile.get("training_profile") == PROFILE and profile.get("objective") == OBJECTIVE
            and type(profile.get("epochs")) is int and profile["epochs"] == 1
            and type(actual_steps) is int and actual_steps == STEPS and type(profile.get("seed")) is int and profile["seed"] == SEED
            and type(profile.get("lr")) is float and profile["lr"] == LEARNING_RATE,
            "one canonical v4 epoch requires exactly eight actual updates and fixed seed/LR")
    require(profile.get("weight_decay") == 0.01 and profile.get("max_grad_norm") == 1.0
            and type(profile.get("max_seconds")) is int and profile["max_seconds"] == 1800
            and profile.get("warm_start") == "pinned-upstream-adapter-and-head",
            "declared fresh warm start and fixed optimizer/resource bounds required")
    require(type(profile.get("optimization")) is dict and canonical(profile["optimization"]) == canonical(_fixed_plan(profile)),
            "saved history objective/membership/masks/weights/control gates differ")


def development_details(metrics, examples):
    result = dict(metrics)
    for name, rows, count_name in (("declared_family_macro", metrics["by_declared_family"], "families"),
                                  ("authored_history_macro", metrics["by_authored_history"], "histories")):
        result[name] = {count_name: len(rows)}
        for field in ("bce", "brier", "positive_recall", "negative_specificity"):
            available = [row[field] for row in rows.values() if row[field] is not None]
            result[name][field] = None if not available else sum(available) / len(available)
            result[name][field + "_strata"] = len(available)
    dev = [example for example in examples if example.partition == "validation"]
    result["masked_callbacks"] = sum(not known for example in dev for known in example.known)
    result["multi_positive_bases"] = sum(sum(known and label == 1.0 for known, label in zip(example.known, example.labels)) > 1 for example in dev)
    for kind in ("candidate", "bundle"):
        result["known_" + kind + "_callbacks"] = sum(known and current == kind for example in dev for known, current in zip(example.known, example.kinds))
    return result


def _metrics(examples, intake, logits):
    return development_details(controlled.development_metrics(examples, intake, logits), examples)


def _prior_controls(examples, intake, plan):
    dev = [example for example in examples if example.partition == "validation"]
    controls = {}
    for name, source in zip(CONTROL_KEYS, ("callback_micro", "per_base_group_mean")):
        fraction = plan["train_only_priors"][source]
        probability = fraction["numerator"] / fraction["denominator"]
        logit = math.log(probability / (1 - probability))
        controls[name] = _metrics(examples, intake, {example.association: [logit] * 10 for example in dev})
    return controls


def pure_prior_controls(examples, intake, plan=None):
    actual = planning(examples, intake)
    require(plan is None or type(plan) is dict and canonical(plan) == canonical(actual), "actual fixed TRAIN-only history plan required")
    return _prior_controls(examples, intake, actual)


def beats_prior_controls(metrics, controls):
    require(type(controls) is dict and set(controls) == set(CONTROL_KEYS), "two raw TRAIN-only controls required")
    for value in [metrics] + list(controls.values()):
        require(all(type(value["callback_micro"][field]) in {int, float} and math.isfinite(value["callback_micro"][field])
                    and value["callback_micro"][field] >= 0 for field in ("bce", "brier")), "finite unweighted prior comparison required")
    return all(metrics["callback_micro"][field] < controls[name]["callback_micro"][field]
               for name in CONTROL_KEYS for field in ("bce", "brier"))


def validate_development(report, profile, steps):
    """Recompute recorded scores from fixed source masks; no hardware proof claim."""
    validate_saved_profile(profile, steps)
    require(type(report) is dict and report["format"] == BUNDLE_FORMAT and report["profile"] == PROFILE
            and report["data_profile"] == controlled.PROFILE and type(report["optimizer_steps"]) is int and report["optimizer_steps"] == steps
            and canonical(report["optimization"]) == canonical(profile["optimization"]), "declared v4 development identity/objective differs")
    require(report["useful_model_claim"] is False and report["calibration_fit"] is False and report["threshold_fitted"] is False
            and report["utility_score"] == "uncalibrated-discrimination-score" and report["utility_is_calibrated_probability"] is False
            and report["test_examples_evaluated"] == report["quarantined_examples_used"] == 0
            and type(report["test_examples_evaluated"]) is type(report["quarantined_examples_used"]) is int,
            "v4 diagnostics cannot invent calibration, reader benefit or test use")
    admission = report["token_admission"]
    require(admission["whole_bases"] == 48 and admission["question_rows"] == 480 and admission["all_rows_preserved"] is True
            and admission["limits"] == controlled.LIMITS, "all whole bases/rows must pass uncropped token admission")
    for field, maximum in (("max_state_tokens", 2048), ("max_complete_row_tokens", 4096), ("max_packed_base_tokens", 65536)):
        controlled.v1.integer(admission[field], maximum, 1)
    resource = report["resource_preflight"]
    require(resource["status"] == "largest-known-base-finite-sequential-forward-backward"
            and resource["whole_question_rows"] == 10 and resource["optimizer_updates"] == 0
            and type(resource["optimizer_updates"]) is int and resource["gradients_cleared"] is True,
            "whole-base zero-update resource admission required")
    witnesses = _source_masks(profile)
    masks = {example.association: example for example in witnesses}
    require(resource["association"] in masks and masks[resource["association"]].partition == "train"
            and resource["known_question_rows"] == sum(masks[resource["association"]].known), "resource gate must use an existing whole TRAIN base")
    controlled.v1.integer(resource["total_row_tokens"], 4096, 1)
    controlled.v1.integer(resource["known_total_row_tokens"], 10 * 4096, 1)
    controlled.v1.integer(resource["finite_gradient_tensors"], 1 << 20, 1)
    require(type(resource["bce"]) in {int, float} and math.isfinite(resource["bce"]) and resource["bce"] >= 0,
            "finite whole-base resource loss required")
    losses = controlled.v1.array(report["training_losses"], 8)
    require(len(losses) == 8 and all(type(loss) in {int, float} and math.isfinite(loss) and loss >= 0 for loss in losses),
            "eight actual finite update-loss records required")
    for stage in ("before_development", "after_development"):
        observation = report[stage]
        require(type(observation["examples"]) is int and observation["examples"] == 24 and observation["threshold_fitted"] is False,
                "complete original fixed-threshold development population required")
        recomputed = _metrics(witnesses, profile, observation["utility_logits"])
        require(canonical(observation["metrics"]) == canonical(recomputed), "reported source/family/mask/STOP/cost metrics differ from recorded logits")
    controls = _prior_controls(witnesses, profile, profile["optimization"])
    require(canonical(report["train_prior_controls"]) == canonical(controls), "reported TRAIN prior controls differ from fixed per-base source witnesses")
    baseline = report["constant_controls"]
    for name, logit in (("constant_probability_half", 0.0), ("select_all", 3.0), ("select_none", -3.0)):
        expected = _metrics(witnesses, profile, {example.association: [logit] * 10 for example in witnesses if example.partition == "validation"})
        require(canonical(baseline[name]) == canonical(expected), "reported constant predictor controls differ")
    require(set(baseline) == {"constant_probability_half", "select_all", "select_none"}, "exact three constant controls required")
    metrics = report["after_development"]["metrics"]
    raw_gate, prior_gate = metrics["coverage_surrogate_gates_passed"], beats_prior_controls(metrics, controls)
    expected = {"unweighted_coverage_surrogate_gates_passed": raw_gate, "train_prior_controls_beaten": prior_gate,
                "coverage_surrogate_gates_passed": raw_gate and prior_gate}
    require(all(type(report[key]) is bool and report[key] == value for key, value in expected.items()),
            "v4 success must join all fixed raw and TRAIN-prior gates")
