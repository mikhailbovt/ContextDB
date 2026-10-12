"""Fixed matched public callback intake; no model, tokenizer or private import.

Artifact pins bind one root-built and independently cold-verified public fixture.
Every admitted semantic row uses the serving codec and expands exactly to v1.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from pathlib import Path

import conditional as v1
import corpus
import lossless
from corpus import canonical, checked_root, fixed_entries, read_json, require, sha_file

PROFILE = "contextdb.kev-public-matched-lossless-bce.v2"
PROJECTION = lossless.PROJECTION
BUNDLE_FORMAT = "contextdb.kev-matched-lossless-development-bundle.v2"
FORMAT = "contextdb.router-corpus.matched-closure.v2"
BUILDER = "contextdb.router-matched-builtin.v2"
GENERATOR = "contextdb.router-matched-synthetic.v2"
EVALUATOR = "synthetic-matched-source-coverage.v2"
CORPUS_BLAKE3 = '8116f4f7ec15be8eb897962b05922b1eff26009b358f83da66cba97129e4dd98'
PINS = {'inputs.json': '1ccb46251dee992936006349298243e847f48d96a5e55ded02386a5ccaad7ecf',
 'lineage.json': '1a7af1b62ebc613e494558e2e30da67429ab0ffc93bf91aaf1c5f368fd3c38a6',
 'manifest.json': '06c4963d611a88daa95b4301f0c84afcf292b6c3868697d7c8187c025d07f8e9',
 'observations.json': '3c83cefd3ad0506c00033ab83f02ad5c1e6c7c8db4a1ba239df719da04a996c1',
 'targets.json': 'e8235b657c91ea6916d013e0412c821cf1913f36f4a6dfbc450112beab00ac40'}
FILE_BYTES = {'inputs.json': 3243538,
 'lineage.json': 275120,
 'manifest.json': 8409,
 'observations.json': 36977725,
 'targets.json': 924319}
EXPECTED = {'callback_partitions': {'quarantined': 0, 'test': 0, 'train': 266, 'validation': 266},
 'case_partitions': {'quarantined': 0, 'test': 0, 'train': 17, 'validation': 17},
 'excluded_model_examples': 0,
 'group_metadata_sha256': 'dab84be7bc6f7a8dcbddf1d655150827172d6845f222a61f154f658e48660ea6',
 'partitions': {'train': 32, 'validation': 32},
 'population_audit': {'authored_history_components': {'train': 8, 'validation': 8},
                      'matched_development_history_components': 8,
                      'matched_development_known_utility_changes': 60,
                      'matched_development_selected_base_pairs': 16,
                      'matched_development_utility_change_history_components': 8,
                      'pairs_are_independent_histories': False,
                      'partitions': {'train': 32, 'validation': 32},
                      'real_conversation_claim': False,
                      'shared_schema_limits_generalization': True,
                      'strata': {'train': {'all_zero': 17,
                                           'bundle_positive': 46,
                                           'bundle_unknown': 8,
                                           'known_negative': 178,
                                           'known_positive': 66,
                                           'mixed': 15,
                                           'multi_positive': 13,
                                           'unknown': 12},
                                 'validation': {'all_zero': 16,
                                                'bundle_positive': 43,
                                                'bundle_unknown': 14,
                                                'known_negative': 174,
                                                'known_positive': 60,
                                                'mixed': 16,
                                                'multi_positive': 12,
                                                'unknown': 22}}},
 'reason_counts': {'already_sufficient': 262,
                   'no_required_coverage_gain': 90,
                   'partial_required_coverage': 34,
                   'required_coverage_gain': 126,
                   'unresolved_task': 20},
 'unsupervised_groups': 2}
LIMITS = dict(v1.LIMITS, callbacks=532)  # Explicit new population; v1 remains 512.
ARTIFACTS = v1.ARTIFACTS
SHARED_SOURCES = {
    "corpus.py": "a5402749e8e2b9ae06606f0e41ded051addf85957b1a3c34add76d934d86fc12",
    "trainer.py": "bb00cfa6ebfa2d956edc5262ceafdf497e881d8a048745479a47a238c31594cc",
    "check.py": "5a37ce05d39df1aca2c6db1ad8a51a2c057dddcc3007d960451959a70725df14",
    "conditional.py": "b3c24f5dfdda29465f4b5cc4d2d0a73a7d3ee44cb312ee2437f4cca57a910827",
    "lossless.py": "1a14e1409ea538ba85bf5f480605c55a84fc3a353783f226693ba3fa4bc1f3a1",
}
UNAVAILABLE = ["measured_reader_marginal_utility", "private_training_export_admission",
               "first_stage_high_recall", "calibration_and_heldout_quality",
               "native_learned_scorer_dispatch", "stage_17_paired_reader_benchmarks"]
LINEAGE_KINDS = {"workspace", "project", "entity", "session", "run", "source_version",
                 "derived_view", "query", "evaluation"}
PARTITIONS = {"train", "validation", "test", "quarantined"}
PROBES = {"missing", "resident", "unresolved"}
QUALITY = {"threshold": 0.5, "bce_below": 0.69315, "brier_below": 0.25,
           "positive_recall_at_least": 0.75, "negative_specificity_at_least": 0.75,
           "exact_stop_at_least": 0.75, "matched_pair_at_least": 0.75}


def digest(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value), "fixed digest required")
    return value


def _pins_installed():
    require(set(PINS) == set(FILE_BYTES) == ARTIFACTS and EXPECTED,
            "matched public corpus pins are not installed")
    digest(CORPUS_BLAKE3)
    for value in PINS.values():
        digest(value)
    require(all(type(size) is int and 0 < size <= LIMITS["file_bytes"] for size in FILE_BYTES.values())
            and sum(FILE_BYTES.values()) <= LIMITS["corpus_bytes"], "fixed joint corpus ceiling")


def validate_shared_sources():
    """Frozen helpers are dependencies, never a mutable replacement v1 profile."""
    directory = checked_root(Path(v1.__file__).resolve().parent)
    require(lossless.v1 is v1 and Path(lossless.__file__).resolve().parent == directory
            and Path(corpus.__file__).resolve().parent == directory,
            "single frozen normalizer and serving codec required")
    for name, expected in SHARED_SOURCES.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.resolve() == path
                and path.stat().st_size <= 1 << 20 and sha_file(path, 1 << 20) == expected,
                "frozen matched dependency differs")
    return dict(SHARED_SOURCES)


def project(input_value):
    """Exact serving projection; no masks or association metadata are arguments."""
    projected = lossless.project(input_value)
    require(lossless.expand(*projected) == v1.project(input_value), "lossless normalization differs")
    return projected


def _reference(value):
    v1.shape(value, {"kind", "domain", "id", "version"})
    v1.enum(value["kind"], LINEAGE_KINDS)
    require(v1.text(value["domain"], 256) and v1.text(value["id"], 256), "empty lineage identity")
    if value["version"] is not None:
        require(v1.text(value["version"], 256), "empty lineage version")
    require(value["kind"] != "source_version" or value["version"] is not None,
            "unversioned original source")
    return canonical(value)


def _metadata(value):
    # V2 fixed generator metadata is host-only and never passed to project().
    v1.shape(value, {"format", "authored_seed_sha256", "shared_research_schema", "histories", "cases"})
    require(value["format"] == "contextdb.router-matched-population.v2"
            and value["shared_research_schema"] == "two-fact-four-candidate-matched-probes.v2",
            "matched generator metadata differs")
    digest(value["authored_seed_sha256"])
    histories, cases = {}, {}
    for item in v1.array(value["histories"], 32):
        v1.shape(item, {"history_id", "authored_program_family", "partition", "seed_sha256",
                        "content_template_ancestors", "claims_independent_real_conversations"})
        history = v1.text(item["history_id"], 256)
        require(history and history not in histories, "duplicate authored history")
        require(v1.text(item["authored_program_family"], 256), "empty authored family")
        require(item["claims_independent_real_conversations"] is False,
                "synthetic programs cannot claim independent real conversations")
        v1.enum(item["partition"], PARTITIONS)
        digest(item["seed_sha256"])
        v1.array(item["content_template_ancestors"], 32)
        require(not item["content_template_ancestors"], "this fixed population has separately authored seeds")
        histories[history] = item
    require(len({item["authored_program_family"] for item in histories.values()}) == len(histories),
            "authored families are not distinct")
    for item in v1.array(value["cases"], 64):
        v1.shape(item, {"case_id", "history_id", "probe"})
        identity = v1.text(item["case_id"], 256)
        require(identity and identity not in cases and item["history_id"] in histories,
                "missing or duplicate case metadata")
        v1.enum(item["probe"], PROBES)
        cases[identity] = item
    for history in histories:
        probes = [item["probe"] for item in cases.values() if item["history_id"] == history]
        require(probes.count("missing") == probes.count("resident") == 1
                and probes.count("unresolved") <= 1, "whole missing/resident case pair required")
    return histories, cases


def _lineage(lineage, metadata, total_cases):
    v1.shape(lineage, {"nodes", "cases", "split", "assignments"})
    histories, info = _metadata(metadata)
    nodes = {}
    for node in v1.array(lineage["nodes"], 8192):
        v1.shape(node, {"reference", "available_at", "parents"})
        key = _reference(node["reference"])
        require(key not in nodes, "duplicate lineage reference")
        v1.integer(node["available_at"])
        parents = [_reference(ref) for ref in v1.array(node["parents"], 256)]
        require(len(parents) == len(set(parents)), "duplicate lineage parent")
        nodes[key] = node
    require(all(_reference(parent) in nodes for node in nodes.values() for parent in node["parents"]),
            "missing transitive lineage parent")
    assignments, cases, closures = {}, {}, {}
    for item in v1.array(lineage["assignments"], 64):
        v1.shape(item, {"example_id", "group_digest", "partition", "window_start", "window_end"})
        identity = v1.text(item["example_id"], 256)
        require(identity not in assignments and identity in info, "case assignment differs")
        digest(item["group_digest"])
        v1.enum(item["partition"], PARTITIONS)
        require(item["partition"] == histories[info[identity]["history_id"]]["partition"],
                "authored history moved between folds")
        require(v1.integer(item["window_start"]) <= v1.integer(item["window_end"]), "reversed lineage time")
        assignments[identity] = item
    for case in v1.array(lineage["cases"], 64):
        v1.shape(case, {"example_id", "logical_domain", "cutoff", "roots"})
        identity = v1.text(case["example_id"], 256)
        require(identity not in cases and identity in assignments, "missing case assignment")
        require(v1.text(case["logical_domain"], 256), "empty logical domain")
        cutoff = v1.integer(case["cutoff"])
        roots = [_reference(ref) for ref in v1.array(case["roots"], 256)]
        require(roots and len(roots) == len(set(roots)), "distinct query roots required")
        active, finished = set(), set()

        def visit(key):
            require(key in nodes and key not in active, "missing or cyclic query lineage")
            if key in finished:
                return
            require(len(active) < 64 and len(finished) < 8192, "query lineage traversal ceiling")
            node = nodes[key]
            require(node["available_at"] <= cutoff and node["reference"]["kind"] != "evaluation",
                    "future annotation entered query-time lineage")
            active.add(key)
            for parent in node["parents"]:
                visit(_reference(parent))
            active.remove(key)
            finished.add(key)

        for key in roots:
            visit(key)
        history = histories[info[identity]["history_id"]]
        anchors = {key for key in finished if nodes[key]["reference"]["kind"] in
                   {"workspace", "project", "entity", "session", "run"}}
        require(len(anchors) == 5 and {nodes[key]["reference"]["kind"] for key in anchors} ==
                {"workspace", "project", "entity", "session", "run"}, "complete authored seed anchors required")
        require(all(nodes[key]["reference"]["domain"] == case["logical_domain"]
                    and nodes[key]["reference"]["version"] == "seed:" + history["seed_sha256"] + ":v2"
                    and not nodes[key]["parents"] for key in anchors), "authored seed version binding differs")
        for key in roots:
            node = nodes[key]
            require(node["reference"]["kind"] == "source_version"
                    and node["reference"]["domain"] == case["logical_domain"]
                    and {_reference(parent) for parent in node["parents"]} == anchors,
                    "original source lost its authored history ancestry")
            digest(node["reference"]["version"])
        cases[identity], closures[identity] = case, finished
    require(set(cases) == set(assignments) == set(info) and len(cases) == total_cases,
            "complete authored case lineage required")
    v1.shape(lineage["split"], {"domains"})
    domains = lineage["split"]["domains"]
    require(type(domains) is dict and set(domains) == {case["logical_domain"] for case in cases.values()},
            "exact logical-domain split inventory required")
    for domain, cutoff in domains.items():
        v1.text(domain, 256)
        v1.shape(cutoff, {"train_until", "validation_until"})
        require(v1.integer(cutoff["train_until"]) < v1.integer(cutoff["validation_until"]),
                "invalid domain-specific time cutoffs")
    for identity, assignment in assignments.items():
        cutoff = domains[cases[identity]["logical_domain"]]
        start, end = assignment["window_start"], assignment["window_end"]
        expected = ("train" if end <= cutoff["train_until"] else
                    "validation" if start > cutoff["train_until"] and end <= cutoff["validation_until"] else
                    "test" if start > cutoff["validation_until"] else "quarantined")
        require(expected == assignment["partition"], "domain time split differs from assigned fold")
    history_groups = defaultdict(set)
    for identity, assignment in assignments.items():
        history_groups[info[identity]["history_id"]].add(assignment["group_digest"])
    require(all(len(groups) == 1 for groups in history_groups.values())
            and len({next(iter(groups)) for groups in history_groups.values()}) == len(histories),
            "authored histories must remain separate transitive components")
    ordered = list(cases)
    for position, left in enumerate(ordered):
        for right in ordered[position + 1:]:
            same = info[left]["history_id"] == info[right]["history_id"]
            shared = closures[left] & closures[right]
            require(same or not shared, "foreign authored history ancestry overlap")
            require(not same or shared, "paired probes lost their common original ancestry")
    return nodes, assignments, cases, histories, info


def _label(row, observation, target, case, nodes):
    v1.shape(target, {"row_id", "evaluation", "feature_digest", "selected_base_digest", "trial_wire_digest",
                      "useful", "reason", "provenance"})
    require(target["row_id"] == observation["row_id"] == row["row_id"], "target row association")
    for field in ("feature_digest", "selected_base_digest", "trial_wire_digest"):
        require(digest(target[field]) == digest(observation[field]), "target callback commitment differs")
    require(v1.integer(target["evaluation"], 128, 1) == observation["evaluation"], "target evaluation differs")
    useful = target["useful"]
    require(useful is None or type(useful) is bool, "independent target type")
    reasons = {True: {"required_coverage_gain"}, False: {"already_sufficient", "no_required_coverage_gain"},
               None: {"partial_required_coverage", "unresolved_task", "non_dispatchable_trial"}}
    v1.enum(target["reason"], reasons[useful])
    require(type(observation["outgoing_fits"]) is bool
            and observation["outgoing_fits"] == row["input"]["budget"]["outgoing_fits"]
            and (observation["outgoing_fits"] or useful is None), "non-dispatchable utility must be unknown")
    provenance = target["provenance"]
    if useful is None:
        require(provenance is None, "unknown target invented known-label provenance")
        return useful
    v1.shape(provenance, {"kind", "evaluator_version", "available_at", "logical_domain", "source_nodes"})
    require(provenance["kind"] == "synthetic_source_set" and provenance["evaluator_version"] == EVALUATOR
            and provenance["available_at"] == observation["known_at"] + 1
            and provenance["logical_domain"] == case["logical_domain"], "label provenance/cutoff differs")
    evaluation = canonical({"kind": "evaluation", "domain": case["logical_domain"],
                            "id": "source-label:" + observation["case_id"], "version": "v2"})
    require(evaluation in nodes and nodes[evaluation]["available_at"] == provenance["available_at"],
            "exact future annotation lineage missing")
    roots = {_reference(ref) for ref in case["roots"]}
    proof = [_reference(ref) for ref in v1.array(provenance["source_nodes"], 256)]
    require(len(proof) == len(roots) and set(proof) == roots
            and {_reference(ref) for ref in nodes[evaluation]["parents"]} == roots,
            "label source lineage association differs")
    return useful


def _proposal_key(state, question):
    # Counterfactual correspondence uses actual seed semantics, not labels/UUIDs.
    _, restored = lossless.expand(state, question)
    trial = lossless._question(restored)["trial"]
    seeds = [dict(block, seed=False, added_closure=False) for block in trial["blocks"] if block["seed"]]
    require(0 < len(seeds) <= 2, "fixed single/pair proposal inventory differs")
    return hashlib.sha256(canonical(seeds)).hexdigest()


def _documents(manifest, inputs, observations, targets, lineage):
    v1.shape(manifest, {"format", "profile", "builder", "generator", "cases", "rows", "artifacts",
                        "generator_metadata"})
    require((manifest["format"], manifest["profile"], manifest["builder"], manifest["generator"]) ==
            (FORMAT, PROFILE, BUILDER, GENERATOR), "matched corpus profile differs")
    total_rows = v1.integer(manifest["rows"], LIMITS["callbacks"], 1)
    total_cases = v1.integer(manifest["cases"], 64, 1)
    nodes, assignments, cases, histories, info = _lineage(lineage, manifest["generator_metadata"], total_cases)
    maps = []
    for batch in (inputs, observations, targets):
        v1.array(batch, LIMITS["callbacks"])
        mapped = {row["row_id"]: row for row in batch}
        require(len(mapped) == len(batch) == total_rows, "duplicate/incomplete callbacks")
        maps.append(mapped)
    source, observed, labels = maps
    require(source.keys() == observed.keys() == labels.keys(), "callback inventories differ")
    grouped, states = defaultdict(list), defaultdict(list)
    excluded, callback_partitions = 0, {fold: 0 for fold in sorted(PARTITIONS)}
    reasons = defaultdict(int)
    for row_id, row in source.items():
        v1.shape(row, {"row_id", "input"})
        v1.text(row_id, 256)
        observation = observed[row_id]
        v1.shape(observation, {"row_id", "case_id", "logical_domain", "known_at", "evaluation", "feature_digest",
                               "request_digest", "selected_base_digest", "trial_wire_digest", "seed_ids", "closure_ids",
                               "selected_origins", "trial_origins", "selected", "trial", "outgoing_fits"})
        identity = observation["case_id"]
        require(identity in assignments, "callback has no history assignment")
        partition = assignments[identity]["partition"]
        callback_partitions[partition] += 1
        if partition not in {"train", "validation"}:
            excluded += 1
            continue  # Excluded before semantic projection, tokenizer or model.
        require(observation["row_id"] == row_id
                and observation["known_at"] == cases[identity]["cutoff"]
                and observation["logical_domain"] == cases[identity]["logical_domain"], "callback cutoff association")
        v1.integer(observation["evaluation"], 128, 1)
        digest(observation["request_digest"])
        useful = _label(row, observation, labels[row_id], cases[identity], nodes)
        reasons[labels[row_id]["reason"]] += 1
        selected = digest(observation["selected_base_digest"])
        if selected not in states[identity]:
            states[identity].append(selected)
        require(len(states[identity]) <= 2, "unexpected selected base cannot be discarded")
        key = identity, partition, selected
        require(len(grouped[key]) < LIMITS["questions"], "whole selected-base proposal ceiling")
        state, question = project(row["input"])
        grouped[key].append((state, question, useful, row_id, len(row["input"]["seed_slots"]) > 1))
    examples, metadata, unsupervised = [], {}, 0
    for key, rows in sorted(grouped.items()):
        example = v1.group_example(key, rows)
        if example is None:
            unsupervised += 1
            continue
        examples.append(example)
        case = info[key[0]]
        ordered = sorted(rows, key=lambda row: canonical(row[1]))
        proposals = [_proposal_key(row[0], row[1]) for row in ordered]
        require(len(proposals) == len(set(proposals)), "duplicate semantic proposal correspondence")
        metadata[example.association] = {"history": case["history_id"],
                                         "family": histories[case["history_id"]]["authored_program_family"],
                                         "case": key[0], "probe": case["probe"], "partition": key[1],
                                         "selection_step": states[key[0]].index(key[2]), "proposals": proposals}
    audit = population_audit(examples, metadata)
    report = {"profile": PROFILE, "projection": PROJECTION, "corpus_manifest_blake3": CORPUS_BLAKE3,
              "corpus_files_sha256": dict(PINS), "limits": dict(LIMITS), "unavailable": list(UNAVAILABLE),
              "partitions": audit["partitions"], "case_partitions": {fold: sum(a["partition"] == fold
                  for a in assignments.values()) for fold in sorted(PARTITIONS)},
              "callback_partitions": callback_partitions, "excluded_model_examples": excluded,
              "unsupervised_groups": unsupervised, "reason_counts": dict(sorted(reasons.items())),
              "population_audit": audit, "group_metadata": metadata,
              "group_metadata_sha256": hashlib.sha256(canonical(metadata)).hexdigest(),
              "shared_sources_sha256": dict(SHARED_SOURCES), "quality_gates": dict(QUALITY),
              "label_semantics": "conditional synthetic source-coverage surrogate; not measured reader utility"}
    require(EXPECTED and all(report[key] == value for key, value in EXPECTED.items()), "fixed matched population differs")
    return examples, report


def load_examples(corpus, seed=20261012):
    _pins_installed()  # Deliberately refuses staged/unbuilt corpus before any read.
    validate_shared_sources()
    root = checked_root(corpus)
    fixed_entries(root, ARTIFACTS)
    paths = {name: root / name for name in ARTIFACTS}
    require(all(path.is_file() and not path.is_symlink() and path.resolve() == path for path in paths.values()),
            "direct regular matched artifacts required")
    sizes = {name: path.stat().st_size for name, path in paths.items()}
    require(sizes == FILE_BYTES, "fixed corpus sizes differ")
    for name, expected in PINS.items():
        require(sha_file(paths[name], sizes[name]) == expected, "only the fixed cold-verified public corpus is supported")
    manifest = read_json(paths["manifest.json"], 64 << 10)
    require(type(manifest.get("artifacts")) is dict and set(manifest["artifacts"]) == ARTIFACTS - {"manifest.json"},
            "fixed artifact inventory differs")
    for name, item in manifest["artifacts"].items():
        v1.shape(item, {"bytes", "digest"})
        require(type(item["bytes"]) is int and item["bytes"] == sizes[name], "artifact size association")
        digest(item["digest"])
    return _documents(manifest, read_json(paths["inputs.json"], sizes["inputs.json"]),
                      read_json(paths["observations.json"], sizes["observations.json"]),
                      read_json(paths["targets.json"], sizes["targets.json"]),
                      read_json(paths["lineage.json"], sizes["lineage.json"]))


def population_audit(examples, metadata):
    require(examples and len(examples) <= 2 * LIMITS["groups_per_fold"]
            and set(metadata) == {example.association for example in examples}, "exact group audit inventory")
    counts, strata, history_counts = {}, {}, {}
    paired = defaultdict(dict)
    for fold in ("train", "validation"):
        group = [example for example in examples if example.partition == fold]
        require(0 < len(group) <= LIMITS["groups_per_fold"], "bounded supervised folds required")
        counts[fold] = len(group)
        strata[fold] = {"all_zero": 0, "mixed": 0, "multi_positive": 0, "known_positive": 0,
                        "known_negative": 0, "unknown": 0, "bundle_positive": 0, "bundle_unknown": 0}
        history_counts[fold] = len({metadata[example.association]["history"] for example in group})
        for example in group:
            require(example.labels and len(example.labels) == len(example.known) == len(example.kinds)
                    == len(metadata[example.association]["proposals"]) <= LIMITS["questions"]
                    and all(type(known) is bool for known in example.known)
                    and all(type(label) is float and label in (0.0, 1.0) for label in example.labels)
                    and any(example.known), "independent masked whole group required")
            positive = sum(known and label == 1.0 for known, label in zip(example.known, example.labels))
            negative = sum(known and label == 0.0 for known, label in zip(example.known, example.labels))
            row = strata[fold]
            row["all_zero"] += positive == 0
            row["mixed"] += positive > 0 and negative > 0
            row["multi_positive"] += positive > 1
            row["known_positive"] += positive
            row["known_negative"] += negative
            row["unknown"] += sum(not known for known in example.known)
            row["bundle_positive"] += sum(kind == "bundle" and known and label == 1.0
                for kind, known, label in zip(example.kinds, example.known, example.labels))
            row["bundle_unknown"] += sum(kind == "bundle" and not known for kind, known in zip(example.kinds, example.known))
            item = metadata[example.association]
            if item["probe"] in {"missing", "resident"}:
                pair = paired[(fold, item["history"], item["selection_step"])]
                require(item["probe"] not in pair, "duplicate matched selected base")
                pair[item["probe"]] = example
    require(strata["train"]["all_zero"] >= 8 and strata["train"]["mixed"] >= 8,
            "measured eight all-zero and eight mixed training bases required")
    pairs = [key for key, value in paired.items() if key[0] == "validation" and set(value) == {"missing", "resident"}]
    paired_histories = {key[1] for key in pairs}
    require(len(pairs) >= 8 and len(paired_histories) >= 8,
            "at least eight matched development authored histories required")
    changes, change_histories = 0, set()
    for key in pairs:
        pair = paired[key]
        rows = {}
        for probe, example in pair.items():
            rows[probe] = {proposal: (label, known) for proposal, label, known in
                zip(metadata[example.association]["proposals"], example.labels, example.known)}
        for proposal in rows["missing"].keys() & rows["resident"].keys():
            before, after = rows["missing"][proposal], rows["resident"][proposal]
            if before == (1.0, True) and after == (0.0, True):
                changes += 1
                change_histories.add(key[1])
    require(len(change_histories) >= 8, "eight measured matched known utility-change histories required")
    return {"partitions": counts, "strata": strata, "authored_history_components": history_counts,
            "matched_development_selected_base_pairs": len(pairs),
            "matched_development_history_components": len(paired_histories),
            "matched_development_known_utility_changes": changes,
            "matched_development_utility_change_history_components": len(change_histories),
            "pairs_are_independent_histories": False,
            "shared_schema_limits_generalization": True, "real_conversation_claim": False}


def validate_saved_profile(profile, steps):
    _pins_installed()
    require(type(profile) is dict and {"profile", "projection", "corpus_manifest_blake3", "corpus_files_sha256",
            "limits", "shared_sources_sha256", "quality_gates", "partitions", "epochs", "group_metadata",
            "group_metadata_sha256"} <= set(profile), "complete saved matched profile required")
    require(profile["profile"] == PROFILE and profile["projection"] == PROJECTION
            and profile["corpus_manifest_blake3"] == CORPUS_BLAKE3 and profile["corpus_files_sha256"] == PINS
            and profile["limits"] == LIMITS and profile["shared_sources_sha256"] == SHARED_SOURCES
            and profile["quality_gates"] == QUALITY, "saved matched corpus/projection differs")
    require(type(profile["group_metadata"]) is dict
            and digest(profile["group_metadata_sha256"]) == hashlib.sha256(canonical(profile["group_metadata"])).hexdigest(),
            "saved matched correspondence commitment differs")
    counts = profile["partitions"]
    v1.shape(counts, {"train", "validation"})
    require(all(type(value) is int and 0 < value <= LIMITS["groups_per_fold"] for value in counts.values())
            and type(profile["epochs"]) is int and profile["epochs"] == 1
            and type(steps) is int and 0 < steps == counts["train"] <= 64,
            "exact one-epoch bounded matched optimization required")
    require(set(EXPECTED) <= set(profile) and all(profile[key] == value for key, value in EXPECTED.items()),
            "saved matched population differs")


def _metrics(rows):
    require(rows, "known evaluation stratum absent")
    bce = brier = 0.0
    tp = tn = fp = fn = 0
    for logit, label in rows:
        bce += max(logit, 0.0) - logit * label + math.log1p(math.exp(-abs(logit)))
        probability = 1 / (1 + math.exp(-logit)) if logit >= 0 else math.exp(logit) / (1 + math.exp(logit))
        brier += (probability - label) ** 2
        predicted = logit >= 0.0  # Fixed independent sigmoid threshold 0.5.
        tp += predicted and label == 1.0
        fp += predicted and label == 0.0
        tn += not predicted and label == 0.0
        fn += not predicted and label == 1.0
    return {"known_callbacks": len(rows), "bce": bce / len(rows), "brier": brier / len(rows),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "positive_recall": None if tp + fn == 0 else tp / (tp + fn),
            "negative_specificity": None if tn + fp == 0 else tn / (tn + fp)}


def development_metrics(examples, intake, logits):
    """Pure finite observation report, with masks and host-only matched ancestry."""
    group = [example for example in examples if example.partition == "validation"]
    require(set(logits) == {example.association for example in group}, "exact development logit inventory")
    metadata = intake["group_metadata"]
    micro, histories, families = [], defaultdict(list), defaultdict(list)
    stops, pairable, bundle = [], defaultdict(dict), []
    for example in group:
        values = logits[example.association]
        require(type(values) is list and len(values) == len(example.known)
                and all(type(value) in {int, float} and math.isfinite(value) for value in values),
                "finite complete development logits required")
        item = metadata[example.association]
        rows = [(value, label) for value, label, known in zip(values, example.labels, example.known) if known]
        micro.extend(rows)
        histories[item["history"]].extend(rows)
        families[item["family"]].extend(rows)
        bundle.extend((value, label) for value, label, known, kind in zip(values, example.labels, example.known, example.kinds)
                      if known and kind == "bundle")
        if not any(known and label == 1.0 for known, label in zip(example.known, example.labels)):
            stops.append(all(value < 0.0 for value, known in zip(values, example.known) if known))
        if item["probe"] in {"missing", "resident"}:
            pairable[(item["history"], item["selection_step"])][item["probe"]] = {
                proposal: (value, label, known) for proposal, value, label, known in
                zip(item["proposals"], values, example.labels, example.known)}
    matched, matched_histories = [], defaultdict(list)
    for (history, _), pair in pairable.items():
        require(set(pair) == {"missing", "resident"}, "missing development counterfactual")
        for proposal in pair["missing"].keys() & pair["resident"].keys():
            missing, resident = pair["missing"][proposal], pair["resident"][proposal]
            if missing[2] and resident[2] and missing[1] == 1.0 and resident[1] == 0.0:
                correct = missing[0] >= 0.0 and resident[0] < 0.0
                matched.append(correct)
                matched_histories[history].append(correct)
    require(stops and matched and len(matched_histories) >= 8,
            "measured STOP and eight matched utility-change history strata required")
    history = {key: _metrics(rows) for key, rows in sorted(histories.items())}
    family = {key: _metrics(rows) for key, rows in sorted(families.items())}
    metrics = _metrics(micro)
    macro = {field: sum(value[field] for value in history.values()) / len(history)
             for field in ("bce", "brier")}
    pair_macro = sum(sum(rows) / len(rows) for rows in matched_histories.values()) / len(matched_histories)
    gates = {"bce": metrics["bce"] < QUALITY["bce_below"], "brier": metrics["brier"] < QUALITY["brier_below"],
             "recall": metrics["positive_recall"] is not None and metrics["positive_recall"] >= 0.75,
             "specificity": metrics["negative_specificity"] is not None and metrics["negative_specificity"] >= 0.75,
             "exact_stop": sum(stops) / len(stops) >= 0.75, "matched_pair": sum(matched) / len(matched) >= 0.75,
             "each_declared_family": all(value["positive_recall"] is not None and value["positive_recall"] >= 0.75
                 and value["negative_specificity"] is not None and value["negative_specificity"] >= 0.75
                 for value in family.values())}
    return {"threshold": 0.5, "callback_micro": metrics, "authored_history_macro": macro,
            "by_authored_history": history, "by_declared_family": family,
            "bundle_callbacks": None if not bundle else _metrics(bundle),
            "all_zero_bases": len(stops), "exact_stop": sum(stops) / len(stops),
            "matched_callback_pairs": len(matched), "matched_pair_correctness": sum(matched) / len(matched),
            "matched_history_components": len(matched_histories), "matched_history_macro": pair_macro,
            "gates": gates, "coverage_surrogate_gates_passed": all(gates.values()),
            "useful_model_claim": False, "real_reader_benefit_verified": False, "test_evaluated": 0}
