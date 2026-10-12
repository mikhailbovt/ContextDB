"""Fixed v4 resident-control data intake; no model, tokenizer or private import.

The native cold verifier is the source of compiler/BLAKE3 evidence. This intake
requires its exact five-file receipt, preserves the shared lossless codec, and
independently joins source coverage only after input-only proposal/cost ordering.
"""
from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import conditional as v1
import corpus
import lossless
import matched
from corpus import canonical, checked_root, fixed_entries, read_json, require, sha_file

PROFILE = "contextdb.kev-public-controlled-resident-data.v4"
PROJECTION = lossless.PROJECTION
FORMAT = "contextdb.router-corpus.controlled-resident.v4"
BUILDER = "contextdb.router-controlled-resident-builtin.v4"
GENERATOR = "contextdb.router-controlled-resident-synthetic.v4"
EVALUATOR = "synthetic-controlled-resident-source-coverage.v4"
CONTROL_POLICY = "actual-reference-source-and-protocol-cost-controls.v4"
SCHEMA = "three-resident-four-candidate-cost-controls.v4"
CORPUS_BLAKE3 = 'faa9476d7d6a85249acc65b4cd19f9c43d41f47c59e71523f55072c077b29950'
PINS = {'inputs.json': 'addd14d67a5e959b3bb1b6ffdd8eb4b8cfa57dac7471e3acd7dfd5a20b849126',
 'lineage.json': 'eff07f365b841aa29e11d84d9543deb5c20e53799a340a84c8d4714040e40f71',
 'manifest.json': '034820912fbc22e8026eb1fd453e4b4e3aa32bbdc0987408d5dd3fb87cda781e',
 'observations.json': '91d66cb5f64d0872adfa8aa5530a5b2a2d49cf83ef5bd15070f546781f99b0c0',
 'targets.json': '06e7d2cf1082efeb3e3580638fc08f2e4e6364e117fd8010ccc2aa55dd523a17'}
FILE_BYTES = {'inputs.json': 2818977,
 'lineage.json': 361680,
 'manifest.json': 13969,
 'observations.json': 31092705,
 'targets.json': 976407}
EXPECTED = {'callback_partitions': {'quarantined': 0, 'test': 0, 'train': 240, 'validation': 240},
 'case_partitions': {'quarantined': 0, 'test': 0, 'train': 24, 'validation': 24},
 'cost_control_audit': {'history_cardinality_contrasts': 32,
                        'known_nonzero_mixed_strata': 92,
                        'policy': 'actual-reference-source-and-protocol-cost-controls.v4'},
 'excluded_model_examples': 0,
 'generator_metadata_sha256': '5085b4ee04cb19f0c63a92b9e185ba0e6ccb29e1cf85d22a779363cf9094e187',
 'group_metadata_sha256': 'c428c686655acf57cc00a6b34ae86c6d8c766f16f11cc9316e82447ca6a11170',
 'partitions': {'train': 24, 'validation': 24},
 'population_audit': {'authored_history_components': {'train': 8, 'validation': 8},
                      'partitions': {'train': 24, 'validation': 24},
                      'real_conversation_claim': False,
                      'resident_probe_groups': 16,
                      'shared_schema_limits_generalization': True,
                      'statistical_independence_claim': False,
                      'strata': {'train': {'all_zero': 8,
                                           'bundle_positive': 48,
                                           'bundle_unknown': 8,
                                           'known_negative': 164,
                                           'known_positive': 64,
                                           'mixed': 16,
                                           'multi_positive': 14,
                                           'unknown': 12},
                                 'validation': {'all_zero': 8,
                                                'bundle_positive': 48,
                                                'bundle_unknown': 8,
                                                'known_negative': 164,
                                                'known_positive': 64,
                                                'mixed': 16,
                                                'multi_positive': 14,
                                                'unknown': 12}}},
 'reason_counts': {'already_sufficient': 160,
                   'no_required_coverage_gain': 168,
                   'partial_required_coverage': 24,
                   'required_coverage_gain': 128},
 'unsupervised_groups': 0}
ARTIFACTS = v1.ARTIFACTS
LIMITS = dict(v1.LIMITS, callbacks=480, groups_per_fold=24, questions=10)
SHARED_SOURCES = dict(matched.SHARED_SOURCES,
    **{"matched.py": "c0f87ae4b7a7b4e9cef966add4513cc52d42d7ee738725dbac79b46bbbfd8c9d"})
SEED_FILES = {
    "queries.json": (26534, "1a14cfa7f550a7090346d3615ebdd0c6866b0dc9efd9952472f441ba41573b15"),
    "annotations.json": (2500, "27959dec2689ede807507a3d08821f2fd1ba994d95fa1988d138a6ece9e7dc54"),
    "ancestry.json": (4031, "fbc5c3ed790f81d5841ec83d2a835c585b9d5a4d97b6816b1d0980c4d5b36d3c"),
}
QUALITY = dict(matched.QUALITY, controlled_cost_contrast_at_least=0.75)
UNAVAILABLE = list(matched.UNAVAILABLE)
PARTITIONS = matched.PARTITIONS
ROLES = {"user": "user_statement", "assistant": "model_generated", "tool": "tool_output"}
OBSERVATION_FIELDS = {"row_id", "case_id", "logical_domain", "known_at", "evaluation", "feature_digest",
    "request_digest", "selected_base_digest", "trial_wire_digest", "seed_ids", "closure_ids",
    "selected_origins", "trial_origins", "selected", "trial", "outgoing_fits"}
REPORT_PINS = {"generator_metadata_sha256", "group_metadata_sha256", "population_audit",
               "cost_control_audit", "partitions", "reason_counts"}
SECTIONS = (("situation", "situation"), ("self_context", "self_context"), ("participants", "participant"),
    ("shared_history", "shared_history"), ("episodes", "episode"), ("facts", "fact"),
    ("relationships", "relationship"), ("preferences", "preference"), ("boundaries", "boundary"),
    ("goals", "goal"), ("decisions", "decision"), ("timeline", "timeline"), ("procedures", "procedure"),
    ("constraints", "constraint"), ("open_loops", "open_loop"), ("conflicts", "conflict"),
    ("unknowns", "unknown"), ("raw_observations", "raw_observation"))


def _sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pins_installed():
    require(set(PINS) == set(FILE_BYTES) == ARTIFACTS and REPORT_PINS <= set(EXPECTED),
            "controlled public corpus receipt is not installed")
    matched.digest(CORPUS_BLAKE3)
    for value in PINS.values():
        matched.digest(value)
    for name in ("generator_metadata_sha256", "group_metadata_sha256"):
        matched.digest(EXPECTED[name])
    require(all(type(size) is int and 0 < size <= LIMITS["file_bytes"] for size in FILE_BYTES.values())
            and sum(FILE_BYTES.values()) <= LIMITS["corpus_bytes"], "fixed joint controlled corpus ceiling")


def validate_shared_sources():
    directory = checked_root(Path(__file__).resolve().parent)
    require(all(Path(module.__file__).resolve().parent == directory for module in (v1, corpus, lossless, matched))
            and lossless.v1 is v1, "one frozen normalizer, codec and pure metric helper required")
    for name, expected in SHARED_SOURCES.items():
        path = directory / name
        require(path.resolve() == path and sha_file(path, 1 << 20) == expected,
                "frozen controlled dependency differs")
    return dict(SHARED_SOURCES)


def project(value):
    projected = lossless.project(value)
    require(lossless.expand(*projected) == v1.project(value), "lossless controlled projection differs")
    return projected


def _seed_assets():
    root = checked_root(Path(__file__).resolve().parents[3] /
        "crates/contextdb-bench/src/router_corpus/conditional/controlled")
    loaded, paths = {}, {}
    for name, (size, digest) in SEED_FILES.items():
        path = root / name
        require(path.resolve() == path and path.stat().st_size == size and sha_file(path, size) == digest,
                "fixed public authoring asset differs")
        paths[name] = path
        if name != "annotations.json":
            loaded[name] = read_json(path, size)
    queries, ancestry = (loaded[name] for name in ("queries.json", "ancestry.json"))
    v1.shape(queries, {"format", "histories"})
    v1.shape(ancestry, {"format", "shared_research_schema", "claims_independent_real_conversations",
                        "claims_statistical_independence", "histories"})
    require(queries["format"] == "contextdb.router-controlled-resident-queries.v4"
            and ancestry["format"] == "contextdb.router-controlled-resident-ancestry.v4"
            and ancestry["shared_research_schema"] == SCHEMA
            and ancestry["claims_independent_real_conversations"] is False
            and ancestry["claims_statistical_independence"] is False, "separate authored v4 assets required")
    histories = {item["id"]: item for item in v1.array(queries["histories"], 16)}
    ancestors = {item["history_id"]: item for item in v1.array(ancestry["histories"], 16)}
    require(len(histories) == len(ancestors) == 16 and histories.keys() == ancestors.keys(),
            "sixteen complete separately authored histories required")
    cases = {}
    for identity, history in histories.items():
        ancestor = ancestors[identity]
        require(ancestor["seed_sha256"] == _sha(history) and ancestor["partition"] == history["partition"]
                and ancestor["authored_program_family"] == history["family"]
                and ancestor["content_template_ancestors"] == history["content_template_ancestors"] == [],
                "canonical whole-query authoring ancestry differs")
        require(history["cutoff"] == 8 and [source["known_at"] for source in history["originals"]]
                == list(range(1, len(history["originals"]) + 1)), "full original source chronology required")
        for probe in history["probes"]:
            case = identity + "-" + probe["id"]
            require(case not in cases, "duplicate resident case")
            cases[case] = {"case_id": case, "history_id": identity, "probe": probe["id"],
                           "resident_source_ids": probe["resident_source_ids"]}
    require(len(cases) == 48 and len({item["family"] for item in histories.values()}) == 16
            and sum(item["partition"] == "train" for item in histories.values()) == 8
            and sum(item["partition"] == "validation" for item in histories.values()) == 8, "fixed fresh folds required")
    return histories, paths["annotations.json"], ancestry, cases


def _recipes(path, histories):
    annotations = read_json(path, SEED_FILES["annotations.json"][0])
    v1.shape(annotations, {"format", "recipes"})
    require(annotations["format"] == "contextdb.router-controlled-resident-annotations.v4", "separate v4 annotation asset required")
    recipes = {item["history_id"]: item for item in v1.array(annotations["recipes"], 16)}
    require(len(recipes) == 16 and recipes.keys() == histories.keys(), "complete annotation recipe inventory required")
    for identity, recipe in recipes.items():
        v1.shape(recipe, {"history_id", "rule", "sufficient_source_sets"})
        sufficient = next(probe["resident_source_ids"] for probe in histories[identity]["probes"] if probe["id"] == "sufficient")
        require(recipe["rule"] in {"additive", "sufficient_union_only"} and len(recipe["sufficient_source_sets"]) == 1
                and len(recipe["sufficient_source_sets"][0]) == 2 and set(recipe["sufficient_source_sets"][0]) == set(sufficient),
                "fixed independently authored two-source coverage proof required")
    return recipes


def _lineage(lineage, metadata, histories, ancestry, info):
    v1.shape(metadata, {"format", "shared_research_schema", "claims_independent_real_conversations",
        "claims_statistical_independence", "reference_controls", "ancestry", "cases"})
    require(metadata["format"] == "contextdb.router-controlled-resident-population.v4"
            and metadata["shared_research_schema"] == SCHEMA and metadata["reference_controls"] == CONTROL_POLICY
            and metadata["claims_independent_real_conversations"] is False
            and metadata["claims_statistical_independence"] is False and metadata["ancestry"] == ancestry
            and metadata["cases"] == list(info.values()), "fixed source-only controlled metadata differs")
    v1.shape(lineage, {"nodes", "cases", "split", "assignments"})
    nodes, cases, assignments, closures = {}, {}, {}, {}
    for node in v1.array(lineage["nodes"], 8192):
        v1.shape(node, {"reference", "available_at", "parents"})
        key = matched._reference(node["reference"])
        require(key not in nodes, "duplicate controlled lineage reference")
        v1.integer(node["available_at"])
        parents = [matched._reference(parent) for parent in v1.array(node["parents"], 256)]
        require(len(parents) == len(set(parents)), "duplicate controlled lineage parent")
        nodes[key] = node
    require(all(matched._reference(parent) in nodes for node in nodes.values() for parent in node["parents"]),
            "missing transitive controlled ancestry")
    for row in v1.array(lineage["assignments"], 48):
        v1.shape(row, {"example_id", "group_digest", "partition", "window_start", "window_end"})
        identity = row["example_id"]
        require(identity in info and identity not in assignments and row["partition"] == histories[info[identity]["history_id"]]["partition"]
                and (row["window_start"], row["window_end"]) == (1, 9), "whole history fold/time assignment differs")
        matched.digest(row["group_digest"])
        assignments[identity] = row
    for case in v1.array(lineage["cases"], 48):
        v1.shape(case, {"example_id", "logical_domain", "cutoff", "roots"})
        identity = case["example_id"]
        require(identity in assignments and identity not in cases and case["cutoff"] == 8, "query-time controlled case differs")
        roots = [matched._reference(ref) for ref in v1.array(case["roots"], 256)]
        history = histories[info[identity]["history_id"]]
        require(len(set(roots)) == len(roots) == len(history["originals"]) + 2, "all originals, working state and query required")
        active, finished = set(), set()

        def visit(key):
            require(key in nodes and key not in active and len(active) < 64, "missing or cyclic controlled lineage")
            if key in finished:
                return
            node = nodes[key]
            require(node["available_at"] <= 8 and node["reference"]["kind"] != "evaluation", "future label entered query lineage")
            active.add(key)
            for parent in node["parents"]:
                visit(matched._reference(parent))
            active.remove(key)
            finished.add(key)

        for key in roots:
            visit(key)
        anchors = {key for key in finished if nodes[key]["reference"]["kind"] != "source_version"}
        require(len(anchors) == 5 and {nodes[key]["reference"]["kind"] for key in anchors}
                == {"workspace", "project", "entity", "session", "run"}, "five full authored anchors required")
        seed = next(row["seed_sha256"] for row in ancestry["histories"] if row["history_id"] == history["id"])
        require(all(nodes[key]["reference"]["domain"] == case["logical_domain"]
                    and nodes[key]["reference"]["version"] == "seed:" + seed + ":v4"
                    and nodes[key]["available_at"] == 1 and not nodes[key]["parents"] for key in anchors), "authored v4 seed binding differs")
        for key in roots:
            node = nodes[key]
            require(node["reference"]["kind"] == "source_version" and node["reference"]["domain"] == case["logical_domain"]
                    and {matched._reference(parent) for parent in node["parents"]} == anchors, "source version lost authored ancestry")
            matched.digest(node["reference"]["version"])
        cases[identity], closures[identity] = case, finished
    require(set(cases) == set(assignments) == set(info), "all forty-eight controlled cases required")
    v1.shape(lineage["split"], {"domains"})
    domains, components = lineage["split"]["domains"], defaultdict(set)
    require(type(domains) is dict and set(domains) == {case["logical_domain"] for case in cases.values()} and len(domains) == 16,
            "exact sixteen history domains required")
    for identity, row in assignments.items():
        components[info[identity]["history_id"]].add((cases[identity]["logical_domain"], row["group_digest"]))
        require(domains[cases[identity]["logical_domain"]] ==
                ({"train_until": 9, "validation_until": 10} if row["partition"] == "train" else {"train_until": 0, "validation_until": 9}),
                "fixed domain-specific temporal split differs")
    require(all(len(value) == 1 for value in components.values())
            and len({next(iter(value))[1] for value in components.values()}) == 16,
            "three probes must share one component per authored history")
    ids = list(cases)
    for index, left in enumerate(ids):
        for right in ids[index + 1:]:
            same = info[left]["history_id"] == info[right]["history_id"]
            require((closures[left] == closures[right]) if same else not closures[left] & closures[right], "foreign or incomplete history ancestry")
    return nodes, assignments, cases


def _span_key(span):
    v1.shape(span, {"event_id", "payload_digest", "start", "end"}, {"span_digest"})
    require(v1.text(span["event_id"], 64) and v1.integer(span["start"]) == 0 and v1.integer(span["end"], 2048, 1), "whole original span required")
    matched.digest(span["payload_digest"])
    require("span_digest" not in span or span["span_digest"] == span["payload_digest"], "whole original span digest differs")
    return canonical({key: span[key] for key in ("event_id", "payload_digest", "start", "end")})


def _originals(history):
    return {source["id"]: source for source in history["originals"]} | {
        "working": {"id": "working", "role": "user", "text": history["working"], "known_at": 8},
        "query": {"id": "query", "role": "user", "text": history["query"], "known_at": 8}}


def _witness_sources(witness, originals, observed_spans, nodes, case):
    require(type(witness) is dict and {"pack", "messages", "outgoing", "choices"} == set(witness), "complete compiler witness required")
    texts = {source["text"]: identity for identity, source in originals.items()}
    require(len(texts) == len(originals), "distinct whole original occurrences required")
    present = {}

    def retain(text, span):
        require(text in texts and span["end"] == len(text.encode("utf-8")), "reconstructed or truncated original refused")
        key, identity = _span_key(span), texts[text]
        require(identity not in present or present[identity] == key, "source occurrence changed within witness")
        reference = matched._reference({"kind": "source_version", "domain": case["logical_domain"],
            "id": span["event_id"], "version": span["payload_digest"]})
        require(reference in nodes and reference in {matched._reference(root) for root in case["roots"]}
                and nodes[reference]["available_at"] == originals[identity]["known_at"], "source chronology/version association differs")
        present[identity] = key

    for evidence in v1.array(witness["pack"]["evidence"], 128):
        if evidence["original_span"] is not None:
            retain(evidence["excerpt"], evidence["original_span"])
    for message in v1.array(witness["messages"], 128):
        raw = v1.text(message["text"]).encode("utf-8")
        for original in v1.array(message["originals"], 128):
            start, end = original["text_start"], original["text_end"]
            require(type(start) is type(end) is int and 0 <= start < end <= len(raw), "visible original byte bounds differ")
            retain(raw[start:end].decode("utf-8"), original["span"])
    keys = [_span_key(span) for span in v1.array(observed_spans, 128)]
    require(len(keys) == len(set(keys)) and set(keys) == set(present.values()), "observed original union differs from actual witness")
    return present


def _resident(history, probe, selected, present):
    resident = set(probe["resident_source_ids"])
    for binding in history["tool_bindings"]:
        if binding["result_source_id"] in resident:
            resident.add(binding["call_source_id"])
    messages = [message for message in selected["messages"] if message["zone"] == "hot_history"]
    expected = [source for source in history["originals"] if source["id"] in resident]
    require(len(messages) == len(expected) and set(present) == resident | {"working", "query"}, "actual fixed resident source set differs")
    for message, source in zip(messages, expected):
        calls = [binding["tool_call_id"] for binding in history["tool_bindings"] if binding["call_source_id"] == source["id"]]
        results = [binding["tool_call_id"] for binding in history["tool_bindings"] if binding["result_source_id"] == source["id"]]
        require(message["role"] == source["role"] and message["text"] == source["text"] and message["tool_calls"] == calls
                and message["tool_result"] == (results[0] if results else None)
                and len(message["originals"]) == 1 and _span_key(message["originals"][0]["span"]) == present[source["id"]],
                "actual original assistant call/result binding differs")
    return resident


def _sections(pack):
    """Exact named PackSections schema in the native PackSections::iter order."""
    sections = pack["sections"]
    v1.shape(sections, {name for name, _ in SECTIONS} - {"raw_observations"}, {"raw_observations"})
    blocks = []
    for name, kind in SECTIONS:
        for block in v1.array(sections.get(name, []), 16):
            require(type(block) is dict and block.get("kind") == kind, "block entered a foreign named section")
            blocks.append(block)
    require(len(blocks) <= 16 and len({block["id"] for block in blocks}) == len(blocks),
            "bounded distinct compiler sections required")
    return blocks


def _proposal(input_value, row, originals):
    trial = row["trial"]["pack"]
    sections = _sections(trial)
    blocks = {block["id"]: block for block in sections}
    evidence = {item["id"]: item for item in trial["evidence"]}
    seeds = row["seed_ids"]
    require(len(seeds) == len(set(seeds)) and len(seeds) in {1, 2} and row["closure_ids"] == seeds, "fixed single/pair closure inventory differs")
    for field in ("seed_slots", "closure_slots"):
        require({sections[index]["id"] for index in input_value[field]} == set(seeds), "local compiler seed-slot association differs")
    by_text = {source["text"]: identity for identity, source in originals.items()}
    source_ids = []
    for seed in seeds:
        block = blocks[seed]
        handles = block["evidence_handles"]
        require(block["kind"] == "raw_observation" and len(handles) == 1, "one actual source per candidate required")
        support = evidence[handles[0]]
        identity = by_text[support["excerpt"]]
        require(originals[identity]["role"] != "assistant" and block["source_class"] == ROLES[originals[identity]["role"]]
                and support["source_class"] == block["source_class"], "source speaker/class association differs")
        source_ids.append(identity)
    source_ids.sort()
    require(len(set(source_ids)) == len(source_ids), "duplicate proposal source occurrence")
    return source_ids


def _text_cost(text):
    v1.text(text)
    tokens, in_word = 0, False
    for character in text:  # Exact reference definition on these fixed public literals.
        word = character.isalnum() or character == "_"
        tokens += (word and not in_word) or (not word and not character.isspace())
        in_word = word
    return {"bytes": len(text.encode("utf-8")), "reference_tokens": tokens, "escaped_bytes": len(canonical(text))}


def _base_shape(base):
    return {zone: [{"role": message["role"], "zone": message["zone"], "text": _text_cost(message["text"]),
                   "tool_calls": len(message["tool_calls"]), "tool_result": message["tool_result"] is not None}
                  for message in base[zone]] for zone in ("control", "working", "hot", "current")}


def _assembly_shape(input_value, witness, origins):
    blocks, native = [], witness["pack"]
    choices = {choice["block_id"]: choice for choice in witness["choices"]}
    sections = _sections(native)
    require(len(sections) == len(input_value["blocks"]), "compiler model block order differs")
    for block, semantic in zip(sections, input_value["blocks"]):
        choice = choices[block["id"]]
        require(block["kind"] == semantic["kind"], "compiler/model block association differs")
        blocks.append({"kind": block["kind"], "level": block["representation"]["level"],
            "alternative": choice["alternative_index"], "generated": choice["generated"],
            "support_count": len(block["evidence_handles"]), "fragment_count": len(block["exact_fragments"]),
            **{key: block[key] for key in ("source_class", "trust", "taints", "interpretation")}, "epistemic": semantic["epistemic"]})
    supports = [{"primary": item["primary"], "source_class": item["source_class"], "taints": item["taints"],
        "original_bytes": None if item["original_span"] is None else item["original_span"]["end"] - item["original_span"]["start"],
        "excerpt_cost": None if item["excerpt"] is None else _text_cost(item["excerpt"])} for item in native["evidence"]]
    messages = [{"zone": item["zone"], "role": item["role"], "original_bytes": [source["span"]["end"] - source["span"]["start"]
        for source in item["originals"]], "calls": len(item["tool_calls"]), "result": item["tool_result"] is not None} for item in witness["messages"]]
    outgoing = witness["outgoing"]
    require(input_value["input_tokens"] == outgoing["input_tokens"] and input_value["wire_bytes"] == len(outgoing["wire"])
            and input_value["count_kind"] == outgoing["count_kind"] == "exact", "actual outgoing cost association differs")
    return {"input_tokens": outgoing["input_tokens"], "wire_bytes": len(outgoing["wire"]), "count_kind": outgoing["count_kind"],
        "added_original_bytes": v1.integer(input_value["added_original_bytes"]), "usage": input_value["usage"],
        "blocks": sorted(map(canonical, blocks)), "supports": sorted(map(canonical, supports)), "messages": messages,
        "source_union_bytes": sorted(span["end"] - span["start"] for span in origins)}


def _cost_shapes(value, row):
    selected = _assembly_shape(value["selected"], row["selected"], row["selected_origins"])
    base = _base_shape(value["base"])
    # canonical bytes are encoded explicitly so no binary value enters JSON.
    for assembly in (selected,):
        for field in ("blocks", "supports"):
            assembly[field] = [item.decode("utf-8") for item in assembly[field]]
    trial = _assembly_shape(value["trial"], row["trial"], row["trial_origins"])
    for field in ("blocks", "supports"):
        trial[field] = [item.decode("utf-8") for item in trial[field]]
    shape = {"base": base, "selected": selected, "trial": trial, "seed_count": len(row["seed_ids"]),
             "closure_count": len(row["closure_ids"]), "memory_limits": value["budget"]["memory"],
             "outgoing_limits": value["budget"]["outgoing"]}
    return _sha([base, selected]), _sha(shape)


def _label(row, target, case, nodes, recipe, selected, trial):
    v1.shape(target, {"row_id", "evaluation", "feature_digest", "selected_base_digest", "trial_wire_digest", "useful", "reason", "provenance"})
    require(target["row_id"] == row["row_id"] and target["evaluation"] == row["evaluation"], "target callback association differs")
    for field in ("feature_digest", "selected_base_digest", "trial_wire_digest"):
        require(matched.digest(target[field]) == matched.digest(row[field]), "target callback commitment differs")
    required = set(recipe["sufficient_source_sets"][0])
    require(recipe["rule"] in {"additive", "sufficient_union_only"} and len(required) == 2, "fixed source-only coverage recipe required")
    expected = ((False, "already_sufficient") if required <= selected else
                (False, "no_required_coverage_gain") if not (required & trial) - selected else
                (None, "partial_required_coverage") if recipe["rule"] == "sufficient_union_only" and not required <= trial else
                (True, "required_coverage_gain"))
    require((target["useful"], target["reason"]) == expected and (target["useful"] is None or type(target["useful"]) is bool),
            "independently rederived source-interval coverage differs")
    provenance = target["provenance"]
    if target["useful"] is None:
        require(provenance is None, "unknown utility invented label provenance")
    else:
        v1.shape(provenance, {"kind", "evaluator_version", "available_at", "logical_domain", "source_nodes"})
        evaluation = matched._reference({"kind": "evaluation", "domain": case["logical_domain"], "id": "source-label:" + row["case_id"], "version": "v4"})
        require(evaluation in nodes and nodes[evaluation]["available_at"] == 9
                and provenance["kind"] == "synthetic_source_set" and provenance["evaluator_version"] == EVALUATOR
                and provenance["available_at"] == 9 and provenance["logical_domain"] == case["logical_domain"]
                and provenance["source_nodes"] == case["roots"] and nodes[evaluation]["parents"] == case["roots"], "exact future v4 annotation provenance differs")
    return target["useful"]


def _documents(manifest, inputs, observations, targets, lineage):
    v1.shape(manifest, {"format", "profile", "builder", "generator", "cases", "rows", "artifacts", "generator_metadata"})
    require((manifest["format"], manifest["profile"], manifest["builder"], manifest["generator"], manifest["cases"], manifest["rows"])
            == (FORMAT, PROFILE, BUILDER, GENERATOR, 48, 480), "exact controlled v4 corpus required")
    histories, annotation_path, ancestry, info = _seed_assets()
    nodes, assignments, cases = _lineage(lineage, manifest["generator_metadata"], histories, ancestry, info)
    maps = []
    for batch in (inputs, observations, targets):
        v1.array(batch, 480)
        mapped = {row["row_id"]: row for row in batch}
        require(len(mapped) == len(batch) == 480, "complete unique controlled callbacks required")
        maps.append(mapped)
    source, observed, labels = maps
    require(source.keys() == observed.keys() == labels.keys(), "callback inventories differ")
    pending, bases, occurrences = defaultdict(list), {}, defaultdict(dict)
    callback_partitions = {fold: 0 for fold in sorted(PARTITIONS)}
    # Association, normalization and cost strata are frozen without reading labels.
    for identity, row in source.items():
        v1.shape(row, {"row_id", "input"})
        observation = observed[identity]
        v1.shape(observation, OBSERVATION_FIELDS)
        case_id = observation["case_id"]
        require(case_id in assignments and observation["row_id"] == identity, "callback has no fixed case assignment")
        fold = assignments[case_id]["partition"]
        callback_partitions[fold] += 1
        if fold not in {"train", "validation"}:
            continue  # Exclude before codec, token admission or any supervision.
        case, item = cases[case_id], info[case_id]
        history = histories[item["history_id"]]
        require(observation["known_at"] == 8 and observation["logical_domain"] == case["logical_domain"]
                and observation["outgoing_fits"] is True and row["input"]["budget"]["outgoing_fits"] is True,
                "dispatchable query-time callback required")
        evaluation = v1.integer(observation["evaluation"], 10, 1)
        require(identity == case_id + ":callback:" + str(evaluation), "actual callback ordinal association differs")
        for field in ("request_digest", "feature_digest", "selected_base_digest", "trial_wire_digest"):
            matched.digest(observation[field])
        originals = _originals(history)
        selected = _witness_sources(observation["selected"], originals, observation["selected_origins"], nodes, case)
        trial = _witness_sources(observation["trial"], originals, observation["trial_origins"], nodes, case)
        _resident(history, item, observation["selected"], selected)
        for name, key in selected.items() | trial.items():
            require(name not in occurrences[history["id"]] or occurrences[history["id"]][name] == key, "original version changed across resident probes")
            occurrences[history["id"]][name] = key
        proposal = _proposal(row["input"], observation, originals)
        require(set(proposal) <= set(history["candidate_source_ids"]), "undeclared or call-ID proposal refused")
        state, question = project(row["input"])
        base_shape, cost = _cost_shapes(row["input"], observation)
        require(history["id"] not in bases or bases[history["id"]] == base_shape, "three resident bases have unequal actual role/protocol cost")
        bases[history["id"]] = base_shape
        key = (case_id, fold, observation["selected_base_digest"])
        pending[key].append((state, question, identity, proposal, cost, set(selected), set(trial), row["input"]["trial"]["added_original_bytes"]))
    require(len(pending) == 48 and callback_partitions == {"train": 240, "validation": 240, "test": 0, "quarantined": 0},
            "fixed forty-eight whole bases and early fold admission required")
    for history in histories.values():
        require(set(occurrences[history["id"]]) == set(_originals(history)), "complete original archive lost a source or actual call")
    # No annotations are parsed until every input, correspondence and cost key is fixed.
    recipes = _recipes(annotation_path, histories)
    examples, metadata, reasons = [], {}, defaultdict(int)
    for key, rows in sorted(pending.items()):
        item, history = info[key[0]], histories[info[key[0]]["history_id"]]
        roster = history["candidate_source_ids"]
        expected = {tuple(sorted(proposal)) for count in (1, 2) for proposal in combinations(roster, count)}
        require(len(rows) == 10 and {tuple(row[3]) for row in rows} == expected, "all four singles and six source pairs required")
        ordered = sorted(rows, key=lambda row: canonical(row[1]))
        joined = []
        for state, question, identity, proposal, cost, selected, trial, added_bytes in ordered:
            target = labels[identity]
            useful = _label(observed[identity], target, cases[key[0]], nodes, recipes[history["id"]], selected, trial)
            reasons[target["reason"]] += 1
            joined.append((state, question, useful, identity, len(proposal) == 2))
        example = v1.group_example(key, joined)
        require(example is not None, "known all-zero/partial resident base cannot be dropped")
        examples.append(example)
        metadata[example.association] = {"history": history["id"], "family": history["family"], "case": key[0],
            "probe": item["probe"], "partition": key[1], "selection_step": 0,
            "proposals": [_sha(row[3]) for row in ordered], "proposal_sources": [row[3] for row in ordered],
            "cost_strata": [row[4] for row in ordered], "added_original_bytes": [row[7] for row in ordered]}
    audit, controls = population_audit(examples, metadata)
    report = {"profile": PROFILE, "projection": PROJECTION, "corpus_manifest_blake3": CORPUS_BLAKE3,
        "corpus_files_sha256": dict(PINS), "seed_assets_sha256": {name: item[1] for name, item in SEED_FILES.items()},
        "limits": dict(LIMITS), "shared_sources_sha256": dict(SHARED_SOURCES), "quality_gates": dict(QUALITY),
        "generator_metadata_sha256": _sha(manifest["generator_metadata"]), "partitions": audit["partitions"],
        "case_partitions": {fold: sum(item["partition"] == fold for item in assignments.values()) for fold in sorted(PARTITIONS)},
        "callback_partitions": callback_partitions, "excluded_model_examples": 0, "unsupervised_groups": 0,
        "reason_counts": dict(sorted(reasons.items())), "population_audit": audit, "cost_control_audit": controls,
        "group_metadata": metadata, "group_metadata_sha256": _sha(metadata), "unavailable": list(UNAVAILABLE),
        "label_semantics": "conditional synthetic source-coverage surrogate; not measured reader utility"}
    return examples, report


def load_examples(corpus_path, seed=20261012):
    _pins_installed()  # Refuse an unbuilt profile before reading any payload.
    validate_shared_sources()
    root = checked_root(corpus_path)
    fixed_entries(root, ARTIFACTS)
    paths = {name: root / name for name in ARTIFACTS}
    require(all(path.resolve() == path and path.is_file() and not path.is_symlink() for path in paths.values()), "direct regular v4 artifacts required")
    sizes = {name: path.stat().st_size for name, path in paths.items()}
    require(sizes == FILE_BYTES, "fixed controlled artifact sizes differ")
    for name, expected in PINS.items():
        require(sha_file(paths[name], sizes[name]) == expected, "only the fixed cold-verified v4 corpus is supported")
    manifest = read_json(paths["manifest.json"], 64 << 10)
    require(type(manifest.get("artifacts")) is dict and set(manifest["artifacts"]) == ARTIFACTS - {"manifest.json"}, "fixed artifact inventory differs")
    for name, item in manifest["artifacts"].items():
        v1.shape(item, {"bytes", "digest"})
        require(type(item["bytes"]) is int and item["bytes"] == sizes[name], "artifact size association differs")
        matched.digest(item["digest"])
    examples, report = _documents(manifest, *(read_json(paths[name], sizes[name]) for name in ("inputs.json", "observations.json", "targets.json", "lineage.json")))
    validate_data_profile(report)
    return examples, report


def population_audit(examples, metadata):
    require(len(examples) == 48 and set(metadata) == {example.association for example in examples}, "fixed controlled example inventory differs")
    counts, strata, histories, mixed = {}, {}, {}, set()
    cost_groups = defaultdict(list)
    correspondence = defaultdict(dict)
    for fold in ("train", "validation"):
        group = [example for example in examples if example.partition == fold]
        require(len(group) == 24, "twenty-four whole bases per fold required")
        counts[fold] = len(group)
        histories[fold] = len({metadata[example.association]["history"] for example in group})
        stats = {"all_zero": 0, "mixed": 0, "multi_positive": 0, "known_positive": 0,
                 "known_negative": 0, "unknown": 0, "bundle_positive": 0, "bundle_unknown": 0}
        for example in group:
            item = metadata[example.association]
            require(example.partition == item["partition"] and len(example.labels) == len(example.known) == len(example.kinds)
                    == len(item["proposals"]) == len(item["proposal_sources"]) == len(item["cost_strata"]) == len(item["added_original_bytes"]) == 10
                    and len(set(item["proposals"])) == 10 and all(type(known) is bool for known in example.known)
                    and all(type(label) is float and label in (0.0, 1.0) for label in example.labels) and any(example.known), "whole independent masked base required")
            require(example.kinds == ["bundle" if len(sources) == 2 else "candidate" for sources in item["proposal_sources"]]
                    and all(proposal == _sha(sources) for proposal, sources in zip(item["proposals"], item["proposal_sources"]))
                    and all(type(added) is int and added >= 0 for added in item["added_original_bytes"]), "input-only proposal/mask cardinality association differs")
            positive = sum(known and label == 1.0 for known, label in zip(example.known, example.labels))
            negative = sum(known and label == 0.0 for known, label in zip(example.known, example.labels))
            stats["all_zero"] += positive == 0
            stats["mixed"] += positive > 0 and negative > 0
            stats["multi_positive"] += positive > 1
            stats["known_positive"] += positive
            stats["known_negative"] += negative
            stats["unknown"] += sum(not known for known in example.known)
            stats["bundle_positive"] += sum(kind == "bundle" and known and label == 1.0
                for kind, known, label in zip(example.kinds, example.known, example.labels))
            stats["bundle_unknown"] += sum(kind == "bundle" and not known for kind, known in zip(example.kinds, example.known))
            pair = correspondence[(fold, item["history"])]
            require(item["probe"] not in pair, "duplicate controlled resident probe")
            pair[item["probe"]] = set(item["proposals"])
            for label, known, sources, cost, added in zip(example.labels, example.known, item["proposal_sources"], item["cost_strata"], item["added_original_bytes"]):
                if known and added > 0:
                    cost_groups[(fold, item["history"], len(sources), cost)].append(label)
        require(stats["all_zero"] >= 8 and stats["mixed"] >= 8, "eight measured all-zero and mixed bases required per fold")
        strata[fold] = stats
    require(histories == {"train": 8, "validation": 8}, "sixteen separate authored history components required")
    for pair in correspondence.values():
        require(set(pair) in ({"sufficient", "irrelevant", "partial"}, {"sufficient", "stale", "partial"})
                and len({frozenset(proposals) for proposals in pair.values()}) == 1, "three complete source-corresponding resident probes required")
    for (fold, history, cardinality, _), labels in cost_groups.items():
        if set(labels) == {0.0, 1.0}:
            mixed.add((fold, history, cardinality))
    require(len(mixed) == 32, "known positive/negative nonzero-source cost contrasts required for every history and cardinality")
    return ({"partitions": counts, "strata": strata, "authored_history_components": histories, "resident_probe_groups": len(correspondence),
             "shared_schema_limits_generalization": True, "real_conversation_claim": False, "statistical_independence_claim": False},
            {"policy": CONTROL_POLICY, "history_cardinality_contrasts": len(mixed),
             "known_nonzero_mixed_strata": sum(set(labels) == {0.0, 1.0} for labels in cost_groups.values())})


def validate_data_profile(profile):
    """Data admission only; no optimizer steps/epochs or legacy profile aliases."""
    _pins_installed()
    require(type(profile) is dict and {"profile", "projection", "corpus_manifest_blake3", "corpus_files_sha256", "limits",
            "seed_assets_sha256", "shared_sources_sha256", "quality_gates", "group_metadata", "group_metadata_sha256"} <= set(profile), "complete saved controlled data profile required")
    require(profile["profile"] == PROFILE and profile["projection"] == PROJECTION and profile["corpus_manifest_blake3"] == CORPUS_BLAKE3
            and profile["corpus_files_sha256"] == PINS and profile["limits"] == LIMITS and profile["shared_sources_sha256"] == SHARED_SOURCES
            and profile["seed_assets_sha256"] == {name: item[1] for name, item in SEED_FILES.items()} and profile["quality_gates"] == QUALITY,
            "saved controlled data/projection contract differs")
    require(type(profile["group_metadata"]) is dict and _sha(profile["group_metadata"]) == profile["group_metadata_sha256"], "saved controlled correspondence commitment differs")
    require(set(EXPECTED) <= set(profile) and all(profile[key] == value for key, value in EXPECTED.items()), "saved fixed controlled metadata/population differs")


def development_metrics(examples, intake, logits):
    """Pure masked metrics with fixed 0.5 decisions and source/cost controls."""
    group = [example for example in examples if example.partition == "validation"]
    require(len(group) == 24 and set(logits) == {example.association for example in group}, "complete v4 development logits required")
    micro, families, histories, probes, cost_groups = [], defaultdict(list), defaultdict(list), defaultdict(dict), defaultdict(list)
    stops = []
    metadata = intake["group_metadata"]
    for example in group:
        item, values = metadata[example.association], logits[example.association]
        require(type(values) is list and len(values) == 10 and all(type(value) in {int, float} and math.isfinite(value) for value in values), "finite whole development logits required")
        rows = [(value, label) for value, label, known in zip(values, example.labels, example.known) if known]
        micro.extend(rows)
        families[item["family"]].extend(rows)
        histories[item["history"]].extend(rows)
        if not any(label == 1.0 and known for label, known in zip(example.labels, example.known)):
            stops.append(all(value < 0.0 for value, known in zip(values, example.known) if known))
        require(item["probe"] not in probes[item["history"]], "duplicate development resident probe")
        probes[item["history"]][item["probe"]] = {proposal: (value, label, known) for proposal, value, label, known in zip(item["proposals"], values, example.labels, example.known)}
        for value, label, known, sources, cost, added in zip(values, example.labels, example.known, item["proposal_sources"], item["cost_strata"], item["added_original_bytes"]):
            if known and added > 0:
                cost_groups[(item["history"], len(sources), cost)].append((value, label))
    paired, cost_pairs, cost_history = [], [], defaultdict(list)
    paired_histories = set()
    for history, variants in probes.items():
        require(set(variants) in ({"sufficient", "irrelevant", "partial"}, {"sufficient", "stale", "partial"}), "whole development resident triple required")
        sufficient = variants["sufficient"]
        for probe, rows in variants.items():
            if probe == "sufficient":
                continue
            require(rows.keys() == sufficient.keys(), "source-level development proposal correspondence differs")
            for proposal, (value, label, known) in rows.items():
                other = sufficient[proposal]
                if known and other[2] and label == 1.0 and other[1] == 0.0:
                    paired.append(value >= 0.0 and other[0] < 0.0)
                    paired_histories.add(history)
    for (history, cardinality, _), rows in cost_groups.items():
        positive = [value for value, label in rows if label == 1.0]
        negative = [value for value, label in rows if label == 0.0]
        contrasts = [p >= 0.0 and n < 0.0 for p in positive for n in negative]
        cost_pairs.extend(contrasts)
        cost_history[(history, cardinality)].extend(contrasts)
    require(len(families) == len(histories) == len(paired_histories) == 8 and len(stops) >= 8 and len(cost_history) == 16
            and all(cost_history.values()) and paired and cost_pairs, "eight actual development history controls required")
    metrics = matched._metrics(micro)
    family = {key: matched._metrics(rows) for key, rows in sorted(families.items())}
    history = {key: matched._metrics(rows) for key, rows in sorted(histories.items())}
    gates = {"bce": metrics["bce"] < QUALITY["bce_below"], "brier": metrics["brier"] < QUALITY["brier_below"],
        "recall": metrics["positive_recall"] is not None and metrics["positive_recall"] >= 0.75,
        "specificity": metrics["negative_specificity"] is not None and metrics["negative_specificity"] >= 0.75,
        "exact_stop": sum(stops) / len(stops) >= 0.75, "matched_pair": sum(paired) / len(paired) >= 0.75,
        "each_declared_family": all(item["positive_recall"] is not None and item["positive_recall"] >= 0.75
            and item["negative_specificity"] is not None and item["negative_specificity"] >= 0.75 for item in family.values()),
        "controlled_cost_contrast": sum(cost_pairs) / len(cost_pairs) >= 0.75,
        "each_history_cardinality_cost_contrast": all(sum(rows) / len(rows) >= 0.75 for rows in cost_history.values())}
    return {"threshold": 0.5, "callback_micro": metrics, "by_declared_family": family, "by_authored_history": history,
        "authored_history_macro": {field: sum(item[field] for item in history.values()) / 8 for field in ("bce", "brier")},
        "all_zero_bases": len(stops), "exact_stop": sum(stops) / len(stops), "matched_callback_pairs": len(paired),
        "matched_pair_correctness": sum(paired) / len(paired), "matched_history_components": len(paired_histories),
        "controlled_cost_pairs": len(cost_pairs), "controlled_cost_contrast_correctness": sum(cost_pairs) / len(cost_pairs),
        "history_cardinality_cost_contrasts": [{"history": key[0], "cardinality": key[1], "pairs": len(rows),
            "correctness": sum(rows) / len(rows)} for key, rows in sorted(cost_history.items())],
        "gates": gates, "coverage_surrogate_gates_passed": all(gates.values()), "useful_model_claim": False,
        "real_reader_benefit_verified": False, "test_evaluated": 0}
