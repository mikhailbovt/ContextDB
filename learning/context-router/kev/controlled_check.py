"""Model-free regression gates for the fixed controlled-resident v4 corpus."""
from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import hashlib
import importlib
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
FORBIDDEN = {"torch", "transformers", "peft", "safetensors", "kev", "tokenizers", "sentencepiece"}
SOURCE_SHA256 = "1b56bd6857408adce3900415697507215328491ebae1de5d75269a5fa0cd3a4d"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refused(operation):
    try:
        operation()
    except ValueError:
        return
    raise ValueError("controlled contract accepted a forbidden variant")


class NoModelImports:
    def find_spec(self, fullname, path=None, target=None):
        require(fullname.split(".")[0] not in FORBIDDEN, "model/tensor/tokenizer import forbidden in pure checks")
        return None


def load(directory):
    directory = Path(directory)
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and directory.resolve() == directory, "absolute resolved tool directory required")
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure process required")
    source = directory / "controlled.py"
    require(source.is_file() and not source.is_symlink() and source.stat().st_size <= 1 << 20
            and hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_SHA256, "fixed controlled data source required")
    sys.meta_path.insert(0, NoModelImports())
    sys.path.insert(0, str(directory))
    module = importlib.import_module("controlled")
    require(Path(module.__file__).resolve() == source, "single frozen data contract required")
    module.validate_shared_sources()
    return module


def data_gate(module, corpus_path):
    examples, intake = module.load_examples(corpus_path)
    require(len(examples) == 48 and intake["partitions"] == {"train": 24, "validation": 24}
            and intake["population_audit"]["authored_history_components"] == {"train": 8, "validation": 8}
            and intake["cost_control_audit"]["history_cardinality_contrasts"] == 32,
            "complete history triples and both nonzero cost cardinalities required")
    totals = [sum(known and label == 1.0 for example in examples for known, label in zip(example.known, example.labels)),
              sum(known and label == 0.0 for example in examples for known, label in zip(example.known, example.labels)),
              sum(not known for example in examples for known in example.known)]
    require(totals == [128, 328, 24] and all(len(example.known) == 10 for example in examples),
            "native known/unknown source census or complete proposal inventory changed")
    module.validate_data_profile(intake)
    root = module.checked_root(corpus_path)
    documents = [module.read_json(root / name, module.FILE_BYTES[name])
                 for name in ("manifest.json", "inputs.json", "observations.json", "targets.json", "lineage.json")]
    return examples, intake, documents


def codec_and_mask_gate(module, examples, documents):
    _, inputs, observations, targets, _ = documents
    # A real complement base checks mask and record ordering together; no
    # invented semantic fixture replaces the admitted input.
    example = next(example for example in examples if not all(example.known)
                   and any(known and label == 1.0 for known, label in zip(example.known, example.labels)))
    by_input = {row["row_id"]: row["input"] for row in inputs}
    by_target = {row["row_id"]: row for row in targets}
    rows = []
    key = None
    for observation in observations:
        candidate = (observation["case_id"], example.partition, observation["selected_base_digest"])
        if hashlib.sha256(module.canonical(candidate)).hexdigest() != example.association:
            continue
        key = candidate
        value = by_input[observation["row_id"]]
        state, question = module.project(value)
        require(module.lossless.expand(state, question) == module.v1.project(value), "whole serving codec expansion changed")
        rows.append((state, question, by_target[observation["row_id"]]["useful"], observation["row_id"], len(observation["seed_ids"]) == 2))
    require(key is not None and len(rows) == 10, "actual whole selected base missing")
    original = module.v1.group_example(key, rows)
    changed = [(state, question, None if useful is None else not useful, identity, bundle)
               for state, question, useful, identity, bundle in reversed(rows)]
    altered = module.v1.group_example(key, changed)
    require(original.record == altered.record == example.record and original.association == altered.association == example.association
            and original.known == altered.known == example.known and original.kinds == altered.kinds == example.kinds
            and original.labels == example.labels and original.labels != altered.labels,
            "labels, host row order or independent masks selected the model record")
    masked = list(rows)
    index = next(index for index, row in enumerate(masked) if row[2] is not None)
    state, question, _, identity, bundle = masked[index]
    masked[index] = (state, question, None, identity, bundle)
    mask_changed = module.v1.group_example(key, masked)
    require(mask_changed.record == original.record and mask_changed.known != original.known, "known mask entered semantic input")
    all_zero = [(state, question, False, identity, bundle) for state, question, _, identity, bundle in rows]
    zero = module.v1.group_example(key, all_zero)
    require(zero is not None and zero.labels == [0.0] * 10 and all(zero.known), "all-zero base was discarded")
    multiple = module.v1.group_example(key, [(state, question, True, identity, bundle)
        for state, question, _, identity, bundle in rows])
    require(multiple.record == zero.record and multiple.labels == [1.0] * 10 and all(multiple.known),
            "independent positives were normalized to one winner")
    value = copy.deepcopy(inputs[0]["input"])
    value["gold"] = True
    refused(lambda: module.project(value))


def commitment_gate(module, intake):
    for profile in (module.v1.PROFILE, module.matched.PROFILE):
        refused(lambda: module.validate_data_profile(dict(intake, profile=profile)))
    retargeted = copy.deepcopy(intake)
    first = next(iter(retargeted["group_metadata"].values()))
    first["family"] += "-retargeted"
    retargeted["group_metadata_sha256"] = hashlib.sha256(module.canonical(retargeted["group_metadata"])).hexdigest()
    refused(lambda: module.validate_data_profile(retargeted))
    retargeted = copy.deepcopy(intake)
    retargeted["cost_control_audit"]["history_cardinality_contrasts"] -= 1
    refused(lambda: module.validate_data_profile(retargeted))
    refused(lambda: module.validate_data_profile(dict(intake, generator_metadata_sha256="0" * 64)))


def source_authority_gate(module, documents):
    manifest, inputs, observations, targets, lineage = documents
    negative = next(index for index, row in enumerate(targets) if row["useful"] is False)
    changed = list(targets)
    changed[negative] = dict(targets[negative], useful=True, reason="required_coverage_gain")
    # No file hash or self-reported metadata is consulted by this pure join.
    refused(lambda: module._documents(manifest, inputs, observations, changed, lineage))
    changed = list(targets)
    changed[negative] = dict(targets[negative], useful=None, reason="partial_required_coverage", provenance=None)
    refused(lambda: module._documents(manifest, inputs, observations, changed, lineage))
    future = dict(lineage, nodes=list(lineage["nodes"]))
    index = next(index for index, row in enumerate(future["nodes"]) if row["reference"]["kind"] == "source_version")
    future["nodes"][index] = dict(future["nodes"][index], available_at=9)
    refused(lambda: module._documents(manifest, inputs, observations, targets, future))


def predictor_gate(module, examples, intake):
    train = [example for example in examples if example.partition == "train"]
    development = [example for example in examples if example.partition == "validation"]
    positive = sum(known and label == 1.0 for example in train for known, label in zip(example.known, example.labels))
    known = sum(sum(example.known) for example in train)
    priors = {"train_micro": Fraction(positive, known), "train_base_mean": sum(
        (Fraction(sum(mask and label == 1.0 for mask, label in zip(example.known, example.labels)), sum(example.known))
         for example in train), Fraction()) / len(train)}
    require(all(0 < value < 1 for value in priors.values()), "TRAIN-only prior controls unavailable")
    controls = {"constant_half": 0.0, "select_all": 3.0, "select_none": -3.0,
                **{name: math.log(float(value) / (1 - float(value))) for name, value in priors.items()}}
    summaries = {}
    baseline = None
    for name, constant in controls.items():
        logits = {example.association: [constant] * 10 for example in development}
        report = module.development_metrics(examples, intake, logits)
        require(report["threshold"] == 0.5 and report["coverage_surrogate_gates_passed"] is False
                and report["matched_pair_correctness"] == report["controlled_cost_contrast_correctness"] == 0.0
                and report["matched_history_components"] == 8 and len(report["history_cardinality_cost_contrasts"]) == 16
                and report["useful_model_claim"] is False and report["real_reader_benefit_verified"] is False,
                "constant predictor became conditional memory or reader-benefit proof")
        micro = report["callback_micro"]
        require(micro["known_callbacks"] == 228 and micro["tp"] + micro["fn"] == 64 and micro["tn"] + micro["fp"] == 164,
                "masked development census changed")
        summaries[name] = {"bce": micro["bce"], "brier": micro["brier"], "quality_gates_passed": False}
        if name == "constant_half":
            baseline = report
    masked_logits = {example.association: [0.0 if known else 1000000.0 for known in example.known] for example in development}
    require(module.development_metrics(examples, intake, masked_logits) == baseline, "unknown logits changed known metrics or STOP/cost gates")
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="absolute fixed controlled-v4 public corpus directory")
    parser.add_argument("--frozen-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    module = load(args.frozen_dir)
    examples, intake, documents = data_gate(module, args.corpus)
    codec_and_mask_gate(module, examples, documents)
    commitment_gate(module, intake)
    source_authority_gate(module, documents)
    controls = predictor_gate(module, examples, intake)
    require(not any(name.split(".")[0] in FORBIDDEN for name in sys.modules), "pure check imported a model dependency")
    print(json.dumps({"status": "pass", "groups": 4, "examples": 48, "callbacks": 480,
        "scope": "controlled-v4-data-authority-codec-masks-and-prediction-controls", "prediction_controls": controls,
        "quality_measured": False, "model_calls": 0, "tokenizer_calls": 0, "tensor_loads": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
