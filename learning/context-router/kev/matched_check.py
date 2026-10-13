"""Pure admission, independent-mask and constant-predictor regression gates."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refused(operation):
    try:
        operation()
    except ValueError:
        return
    raise ValueError("expected strict refusal")


def load(directory):
    directory = Path(directory)
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), "frozen source directory")
    helper = directory / "lossless_check.py"
    require(helper.is_file() and not helper.is_symlink() and helper.stat().st_size <= 1 << 20
            and hashlib.sha256(helper.read_bytes()).hexdigest() ==
            "2657c43315083562bee0658895d35ba5340f6cba852aaefcc118c07e1fd94eaf", "fixed pure fixture helper")
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("matched", Path(__file__).with_name("matched.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_shared_sources()
    import lossless_check
    require(Path(lossless_check.__file__).resolve() == helper.resolve(), "fixture import path")
    return module, lossless_check


def identity_gate(module):
    require(module.PROFILE != module.v1.PROFILE and module.BUNDLE_FORMAT != module.v1.BUNDLE_FORMAT
            and module.FORMAT != module.v1.FORMAT and module.GENERATOR != module.v1.GENERATOR,
            "new data/profile/bundle contracts must differ")
    require(module.LIMITS["callbacks"] == 532 and module.v1.LIMITS["callbacks"] == 512
            and (module.LIMITS["state_tokens"], module.LIMITS["row_tokens"], module.LIMITS["packed_tokens"])
            == (2048, 4096, 65536), "only declared matched population ceiling differs")
    # Even an existing directory cannot supply staged intake before real pinning.
    if not module.PINS:
        refused(lambda: module.load_examples(Path(__file__).resolve().parent))
    legacy = {"profile": module.v1.PROFILE, "projection": module.v1.PROJECTION,
              "corpus_manifest_blake3": module.v1.CORPUS_BLAKE3,
              "corpus_files_sha256": module.v1.PINS, "limits": module.v1.LIMITS}
    refused(lambda: module.validate_saved_profile(legacy, 24))
    if module.PINS:
        forged = {**module.EXPECTED, "profile": module.PROFILE, "projection": module.PROJECTION,
                  "corpus_manifest_blake3": module.CORPUS_BLAKE3, "corpus_files_sha256": module.PINS,
                  "limits": module.LIMITS, "shared_sources_sha256": module.SHARED_SOURCES,
                  "quality_gates": module.QUALITY, "epochs": 1, "group_metadata": {},
                  "group_metadata_sha256": hashlib.sha256(module.canonical({})).hexdigest()}
        refused(lambda: module.validate_saved_profile(forged, module.EXPECTED["partitions"]["train"]))


def semantic_group_gate(module, helper):
    value = helper.fixture(module.v1)
    state, question = module.project(value)
    require(module.lossless.expand(state, question) == module.v1.project(value), "serving/train exact expansion")
    second = copy.deepcopy(value)
    second["trial"]["blocks"][0]["exact_fragments"][0]["value"] = "A distinct second optional literal."
    second_state, second_question = module.project(second)
    require(state == second_state and question != second_question, "actual selected base shared by distinct proposals")
    rows = [(state, question, False, "parent-only-a", False),
            (second_state, second_question, False, "parent-only-b", True)]
    zero = module.v1.group_example(("host-case", "train", "host-digest"), rows)
    require(zero is not None and zero.known == [True, True] and zero.labels == [0.0, 0.0],
            "all-zero group remains supervised")
    multiple = [(row[0], row[1], True, row[3], row[4]) for row in rows]
    multi = module.v1.group_example(("host-case", "train", "host-digest"), multiple)
    require(multi.labels == [1.0, 1.0] and multi.known == [True, True],
            "multiple useful proposals remain independently positive")
    unknown = [(row[0], row[1], None, row[3], row[4]) for row in rows]
    require(module.v1.group_example(("host-case", "train", "host-digest"), unknown) is None,
            "all-unknown group excluded")
    useful = [(rows[0][0], rows[0][1], True, rows[0][3], rows[0][4]),
              (rows[1][0], rows[1][1], None, rows[1][3], rows[1][4])]
    masked = module.v1.group_example(("host-case", "train", "host-digest"), useful)
    reversed_labels = [(row[0], row[1], not row[2] if row[2] is not None else None, row[3], row[4])
                       for row in useful]
    changed = module.v1.group_example(("host-case", "train", "host-digest"), list(reversed(reversed_labels)))
    require(masked.record == changed.record and masked.known == changed.known
            and masked.labels != changed.labels, "labels/masks do not choose record order")
    prose = value["base"]["current"][0]["text"]
    require(prose in module.lossless.expand(state, question)[0]
            and "39c406a2-773c-4c73-a1c3-3ad091968b19" in prose, "literal UUID prose retained")
    for key in ("label", "gold", "case_id", "family", "partition", "source_id"):
        mutated = copy.deepcopy(value)
        mutated[key] = "forbidden"
        refused(lambda: module.project(mutated))
    changed_hot = copy.deepcopy(value)
    changed_hot["base"]["hot"][1]["tool_result"] = 900
    refused(lambda: module.project(changed_hot))
    changed_allowance = copy.deepcopy(value)
    for key in module.v1.VOLATILE:
        changed_allowance["budget"][key] += 100000
    require(module.project(changed_allowance) == (state, question), "allowances stay outside semantic record")


def lineage_gate(module):
    source = {"kind": "source_version", "domain": "train-domain", "id": "original", "version": "f" * 64}
    anchors = [{"kind": kind, "domain": "train-domain", "id": kind, "version": "seed:" + "b" * 64 + ":v2"}
               for kind in ("workspace", "project", "entity", "session", "run")]
    cases = [{"example_id": f"sample-{probe}", "logical_domain": "train-domain", "cutoff": 6,
              "roots": [source]} for probe in ("missing", "resident")]
    metadata = {"format": "contextdb.router-matched-population.v2", "authored_seed_sha256": "a" * 64,
                "shared_research_schema": "two-fact-four-candidate-matched-probes.v2",
                "histories": [{"history_id": "sample", "partition": "train", "authored_program_family": "family-a",
                    "content_template_ancestors": [], "seed_sha256": "b" * 64,
                    "claims_independent_real_conversations": False}],
                "cases": [{"case_id": case["example_id"], "history_id": "sample", "probe": probe}
                          for case, probe in zip(cases, ("missing", "resident"))]}
    lineage = {"nodes": [{"reference": source, "available_at": 1, "parents": anchors}]
                        + [{"reference": ref, "available_at": 1, "parents": []} for ref in anchors], "cases": cases,
               "split": {"domains": {"train-domain": {"train_until": 10, "validation_until": 20}}},
               "assignments": [{"example_id": case["example_id"], "group_digest": "c" * 64,
                                "partition": "train", "window_start": 1, "window_end": 6} for case in cases]}
    module._lineage(lineage, metadata, 2)
    future = copy.deepcopy(lineage)
    future["nodes"][0]["available_at"] = 7
    refused(lambda: module._lineage(future, metadata, 2))
    cycle = copy.deepcopy(lineage)
    cycle["nodes"][0]["parents"] = [copy.deepcopy(source)]
    refused(lambda: module._lineage(cycle, metadata, 2))
    wrong_fold = copy.deepcopy(lineage)
    wrong_fold["assignments"][0]["partition"] = "validation"
    refused(lambda: module._lineage(wrong_fold, metadata, 2))
    wrong_window = copy.deepcopy(lineage)
    wrong_window["assignments"][0]["window_start"] = 11
    wrong_window["assignments"][0]["window_end"] = 12
    refused(lambda: module._lineage(wrong_window, metadata, 2))
    # Pair probes remain one authored component even when their public case names differ.
    divided = copy.deepcopy(lineage)
    divided["assignments"][1]["group_digest"] = "d" * 64
    refused(lambda: module._lineage(divided, metadata, 2))


def population(module, helper, development_histories=8):
    state, first = module.project(helper.fixture(module.v1))
    changed = helper.fixture(module.v1)
    changed["trial"]["blocks"][0]["exact_fragments"][0]["value"] = "Distinct paired source."
    second_state, second = module.project(changed)
    require(second_state == state, "fixture selected base")
    examples, metadata = [], {}
    for fold, count in (("train", 8), ("validation", development_histories)):
        for history in range(count):
            for step in (0, 1):
                for probe in ("missing", "resident"):
                    labels = [True, False] if probe == "missing" else [False, False]
                    rows = [(state, question, label, "opaque-host-row", index == 1)
                            for index, (question, label) in enumerate(zip((first, second), labels))]
                    key = (f"{fold}-history-{history}-{probe}", fold, f"state-{step}")
                    example = module.v1.group_example(key, rows)
                    ordered = sorted(rows, key=lambda row: module.canonical(row[1]))
                    proposals = [module._proposal_key(row[0], row[1]) for row in ordered]
                    examples.append(example)
                    metadata[example.association] = {"history": f"{fold}-history-{history}",
                        "family": f"{fold}-family-{history}", "case": key[0], "probe": probe,
                        "partition": fold, "selection_step": step, "proposals": proposals}
    return examples, metadata


def population_and_metrics_gate(module, helper):
    examples, metadata = population(module, helper)
    audit = module.population_audit(examples, metadata)
    require(audit["partitions"] == {"train": 32, "validation": 32}
            and audit["matched_development_selected_base_pairs"] == 16
            and audit["matched_development_history_components"] == 8
            and audit["matched_development_utility_change_history_components"] == 8,
            "selected bases must not inflate authored-history count")
    short, short_metadata = population(module, helper, development_histories=6)
    refused(lambda: module.population_audit(short, short_metadata))
    no_contrast = copy.deepcopy(examples)
    for example in no_contrast:
        item = metadata[example.association]
        if example.partition == "validation" and item["history"].endswith("-7") and item["probe"] == "missing":
            example.labels = [0.0] * len(example.labels)
    refused(lambda: module.population_audit(no_contrast, metadata))
    zero_predictions = {example.association: [-3.0] * len(example.known) for example in no_contrast
                        if example.partition == "validation"}
    refused(lambda: module.development_metrics(no_contrast, {"group_metadata": metadata}, zero_predictions))
    development = [example for example in examples if example.partition == "validation"]
    perfect = {example.association: [3.0 if label else -3.0 for label in example.labels] for example in development}
    report = module.development_metrics(examples, {"group_metadata": metadata}, perfect)
    require(report["coverage_surrogate_gates_passed"] is True and report["matched_history_components"] == 8
            and report["matched_pair_correctness"] == report["exact_stop"] == 1.0
            and report["useful_model_claim"] is False and report["real_reader_benefit_verified"] is False,
            "perfect surrogate observation does not prove reader utility")
    for constant in (-3.0, 0.0, 3.0):
        logits = {example.association: [constant] * len(example.known) for example in development}
        bad = module.development_metrics(examples, {"group_metadata": metadata}, logits)
        require(bad["coverage_surrogate_gates_passed"] is False and bad["matched_pair_correctness"] == 0.0,
                "constant prediction cannot pass conditional utility-change gate")
    one = development[0]
    missing = dict(perfect)
    missing.pop(one.association)
    refused(lambda: module.development_metrics(examples, {"group_metadata": metadata}, missing))
    nonfinite = copy.deepcopy(perfect)
    nonfinite[one.association][0] = float("nan")
    refused(lambda: module.development_metrics(examples, {"group_metadata": metadata}, nonfinite))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-dir", required=True)
    args = parser.parse_args()
    module, helper = load(args.frozen_dir)
    identity_gate(module)
    semantic_group_gate(module, helper)
    lineage_gate(module)
    population_and_metrics_gate(module, helper)
    require("torch" not in sys.modules and "transformers" not in sys.modules, "no model imports")
    print(json.dumps({"status": "pass", "groups": 4, "model_calls": 0, "tokenizer_calls": 0,
                      "scope": "matched-profile-pure-admission-and-masked-metrics",
                      "actual_corpus_loaded": False, "quality_measured": False}, sort_keys=True))


if __name__ == "__main__":
    main()
