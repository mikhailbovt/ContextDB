"""Fixed public compiler-callback intake and a shared conditional Kev projection."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict

from corpus import Example, canonical, checked_root, fixed_entries, read_json, require, sha_file

PROFILE = "contextdb.kev-public-synthetic-rendered-closure-bce.v1"
PROJECTION = "contextdb.kev-rendered-closure-projection.v1"
BUNDLE_FORMAT = "contextdb.kev-rendered-closure-development-bundle.v1"
FORMAT = "contextdb.router-corpus.rendered-closure.v1"
FEATURE_FORMAT = "contextdb.routing_features.semantic.v1"
BUILDER = "contextdb.router-conditional-builtin.v1"
GENERATOR = "contextdb.router-conditional-synthetic.v1"
# Actual built and cold-verified public fixture; hashes never grant training rights.
CORPUS_BLAKE3 = "ef04265b868160f81902b5144a0115934fe0af10bcd6a59843eae20f3a286eac"
PINS = {
    "inputs.json": "ca5a00bc51fe658755540c731785f393526ac4e4d1e88fe1a40dc61d54e0e0bc",
    "lineage.json": "cacf85c181a4acbc3a6dc5d874221c80fe8624bacb9ce318e736cbffb7c8a16e",
    "manifest.json": "a507f56b9ea842e181dbe5c8c8045f6a347fd19455300a08d1011c1d17724dae",
    "observations.json": "4fa9df4db812d43023dd97b796d40000f4eb2caa769596c96d3b57033985969a",
    "targets.json": "f3c9b1ba86f0a288d6a78784bb66b92cd04bec9f660de4f64c907126fbc85476",
}
FILE_BYTES = {"inputs.json": 1671969, "lineage.json": 230692, "manifest.json": 706,
              "observations.json": 18573929, "targets.json": 409268}
EXPECTED = {"case_partitions": {"train": 12, "validation": 12, "test": 12, "quarantined": 12},
            "callback_partitions": {"train": 67, "validation": 67, "test": 67, "quarantined": 67},
            "partitions": {"train": 24, "validation": 24}, "excluded_model_examples": 134,
            "unsupervised_groups": 2}
LIMITS = {"file_bytes": 64 << 20, "corpus_bytes": 64 << 20, "input_bytes": 2 << 20,
          "callbacks": 512, "groups_per_fold": 64, "questions": 16,
          "state_bytes": 64 << 10, "branch_bytes": 64 << 10,
          "state_tokens": 2048, "row_tokens": 4096, "packed_tokens": 65536}
UNAVAILABLE = ["measured_reader_marginal_utility", "private_training_export_admission",
               "calibration_and_heldout_quality", "native_learned_scorer_dispatch"]
ARTIFACTS = {"manifest.json", "inputs.json", "observations.json", "targets.json", "lineage.json"}
VOLATILE = {"remaining_work", "remaining_bytes", "remaining_timeout_micros",
            "remaining_scorer_work", "remaining_scorer_micros", "remaining_evaluations"}
FIELDS = {"reason", "missing_facet", "question"}
ZONES = {"control", "tool_definitions", "working_state", "memory", "evidence", "hot_history",
         "current_turn", "provider_continuation"}
ROLES = {"system", "developer", "user", "assistant", "tool"}
KINDS = {"situation", "self_context", "participant", "shared_history", "episode", "fact",
         "relationship", "preference", "boundary", "goal", "decision", "timeline", "procedure",
         "constraint", "open_loop", "conflict", "unknown", "raw_observation"}
SOURCES = {"user_statement", "shared_conversation", "repository", "tool_output", "external_document",
           "sensor", "deterministic_derivation", "model_generated", "imported"}
USAGE = {"rendered_tokens", "control_tokens", "data_tokens", "blocks", "evidence_blocks",
         "raw_evidence_tokens", "history_tokens", "conflict_tokens", "serialized_bytes"}
MEMORY = {"hard_tokens", "soft_tokens", "max_blocks", "max_evidence_blocks", "max_raw_evidence_tokens",
          "max_history_tokens", "max_conflict_tokens", "max_serialized_bytes", "max_selection_evaluations"}
OUTGOING = {"max_input_tokens", "safety_tokens", "max_wire_bytes"}


def shape(value, keys, optional=()):
    require(type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional),
            "unsupported conditional fields")


def integer(value, maximum=(1 << 63) - 1, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, "bounded integer required")
    return value


def text(value, maximum=16384):
    require(type(value) is str and len(value) <= maximum and len(value.encode("utf-8")) <= maximum,
            "semantic text ceiling; truncation is forbidden")
    return value


def array(value, maximum):
    require(type(value) is list and len(value) <= maximum, "conditional inventory ceiling")
    return value


def enum(value, values):
    require(type(value) is str and value in values, "unsupported conditional enum")
    return value


def natural(value):
    value = text(value, 256)
    require(value and not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-|[0-9a-f]{64}|synthetic:|raw:|evidence:|group-\d", value),
            "opaque metadata is not a natural field")
    return value


def bounded_canonical(value, maximum):
    """Stop serialization at the cap instead of first building an oversized copy."""
    parts, size = [], 0
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for chunk in encoder.iterencode(value):
        part = chunk.encode("utf-8")
        size += len(part)
        require(size <= maximum, "conditional serialized byte ceiling; no truncation")
        parts.append(part)
    return b"".join(parts)


def bounded_tree(value):
    """Bound borrowed input before canonical copies, sorting or projection."""
    remaining = [LIMITS["input_bytes"], 65536]

    def visit(item, depth):
        require(depth <= 32, "conditional nesting ceiling")
        remaining[1] -= 1
        require(remaining[1] >= 0, "conditional node ceiling")
        if type(item) is str:
            require(len(item) <= remaining[0], "conditional input ceiling")
            remaining[0] -= len(item.encode("utf-8"))
        elif type(item) is dict:
            require(len(item) <= 128, "conditional object ceiling")
            for key, child in item.items():
                require(type(key) is str, "string key required")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 1024, "conditional list ceiling")
            for child in item:
                visit(child, depth + 1)
        else:
            require(item is None or type(item) in {bool, int}, "unsupported conditional scalar")
            remaining[0] -= 24
        require(remaining[0] >= 0, "conditional input ceiling")

    visit(value, 0)
    bounded_canonical(value, LIMITS["input_bytes"])


def numeric(value, keys):
    shape(value, keys)
    return {key: integer(value[key]) for key in sorted(keys)}


def _assembly(value, seeds=None, closure=None):
    seeds = [] if seeds is None else seeds
    closure = [] if closure is None else closure
    shape(value, {"blocks", "supports", "rendered_originals", "input_tokens", "count_kind", "wire_bytes",
                  "added_original_bytes", "usage"})
    supports = []
    for item in array(value["supports"], 128):
        shape(item, {"excerpt", "primary", "source_class", "original_bytes"})
        require(type(item["primary"]) is bool, "support primary flag")
        supports.append({"excerpt": None if item["excerpt"] is None else text(item["excerpt"]),
                         "primary": item["primary"], "source_class": enum(item["source_class"], SOURCES),
                         "original_bytes": None if item["original_bytes"] is None else integer(item["original_bytes"])})
    support_order = sorted(range(len(supports)), key=lambda i: canonical(supports[i]))
    support_slots = {old: new for new, old in enumerate(support_order)}
    remaining = LIMITS["branch_bytes"] - sum(len(bounded_canonical(s, LIMITS["branch_bytes"])) for s in supports)
    require(remaining >= 0, "conditional support material ceiling")
    blocks = array(value["blocks"], 64)
    for slots in (seeds, closure):
        array(slots, 64)
        require(all(type(i) is int and 0 <= i < len(blocks) for i in slots) and len(slots) == len(set(slots)),
                "invalid local block correspondence")
    projected = []
    for index, block in enumerate(blocks):
        shape(block, {"kind", "representation", "exact_fragments", "epistemic", "interpretation", "source_class",
                      "support", "valid_time", "facets", "support_slots", "use_action", "directive_reason",
                      "alternative_index"}, {"conflict", "unknown"})
        kind = enum(block["kind"], KINDS)
        rep = block["representation"]
        shape(rep, {"level", "summary", "fields", "omitted_facets"})
        enum(rep["level"], {"l0_orientation", "l1_summary", "l2_structured", "l3_evidence", "l4_raw"})
        fields = rep["fields"]
        if kind == "raw_observation":
            require(fields is None and rep["summary"] is None, "raw preview metadata refused")
        else:
            require(type(fields) is dict and set(fields) <= FIELDS, "unprojected native fields refused")
            fields = {natural(key): text(val) for key, val in sorted(fields.items())}
            text(rep["summary"])
        representation = {"level": rep["level"], "summary": rep["summary"], "fields": fields,
                          "omitted_facets": sorted(natural(x) for x in array(rep["omitted_facets"], 64))}
        require(not representation["omitted_facets"] and not block["facets"],
                "undeclared facet vocabulary refused by this fixed synthetic profile")
        fragments = []
        for fragment in array(block["exact_fragments"], 64):
            shape(fragment, {"label", "value"})
            fragments.append({"label": natural(fragment["label"]), "value": text(fragment["value"])})
        epistemic = block["epistemic"]
        shape(epistemic, {"basis", "acceptance", "conflict", "lifecycle"})
        enum(epistemic["basis"], {"observation", "actor_assertion", "model_inference", "deterministic_derivation",
                                  "human_adjudication", "hypothesis"})
        enum(epistemic["acceptance"], {"proposed", "validated", "accepted", "consolidated", "rejected"})
        enum(epistemic["lifecycle"], {"active", "historical", "superseded", "retracted", "suppressed", "deleted"})
        shape(epistemic["conflict"], {"state"})
        enum(epistemic["conflict"]["state"], {"none", "disputed", "in_conflict", "resolved"})
        support = block["support"]
        shape(support, {"state"}, {"reason"})
        enum(support["state"], {"supported", "unsupported"})
        require((support["state"] == "unsupported") == ("reason" in support), "support reason binding")
        if "reason" in support:
            text(support["reason"])
        validity = block["valid_time"]
        if validity is not None:
            shape(validity, {"start", "end"})
            integer(validity["start"], minimum=-(1 << 63))
            if validity["end"] is not None:
                integer(validity["end"], minimum=-(1 << 63))
                require(validity["end"] > validity["start"], "invalid semantic time range")
        handles = array(block["support_slots"], 128)
        require(all(type(h) is int and h in support_slots for h in handles) and len(handles) == len(set(handles)),
                "invalid local support correspondence")
        if block["alternative_index"] is not None:
            integer(block["alternative_index"], (1 << 32) - 1)
        enum(block["interpretation"], {"factual_data", "historical_data", "constraint_data", "style_signal",
                                      "hypothesis_only", "unknown_marker", "conflict_alternatives"})
        enum(block["source_class"], SOURCES)
        for key, allowed in (("use_action", {"mention_naturally", "use_silently", "constraint_only", "style_only"}),
                             ("directive_reason", {"policy_allows_mention", "mention_denied", "explicit_request_required",
                                                   "constraint_semantics", "style_semantics"})):
            if block[key] is not None:
                enum(block[key], allowed)
        item = {key: block[key] for key in ("kind", "epistemic", "interpretation", "source_class", "support",
                                           "valid_time", "use_action", "directive_reason")}
        item.update(representation=representation, exact_fragments=fragments,
                    facets=sorted(natural(x) for x in array(block["facets"], 64)),
                    supports=sorted((supports[h] for h in handles), key=canonical))
        if "conflict" in block:
            conflict = block["conflict"]
            shape(conflict, {"blocking", "alternatives", "resolved", "rationale"})
            require(type(conflict["blocking"]) is bool and type(conflict["resolved"]) is bool, "conflict flags")
            integer(conflict["alternatives"], 64)
            if conflict["rationale"] is not None:
                text(conflict["rationale"])
            item["conflict"] = conflict
        if "unknown" in block:
            unknown = block["unknown"]
            shape(unknown, {"question", "reason", "blocking"})
            text(unknown["question"])
            text(unknown["reason"])
            require(type(unknown["blocking"]) is bool, "Unknown blocking flag")
            item["unknown"] = unknown
        # Local seed/closure meaning survives semantic reordering, not opaque ID order.
        if seeds or closure:
            item.update(seed=index in seeds, added_closure=index in closure)
        key = bounded_canonical(item, remaining)
        remaining -= len(key)
        projected.append((key, item))
    originals = []
    for original in array(value["rendered_originals"], 128):
        shape(original, {"zone", "role", "text"})
        item = {"zone": enum(original["zone"], ZONES), "role": enum(original["role"], ROLES),
                "text": text(original["text"])}
        remaining -= len(bounded_canonical(item, remaining))
        originals.append(item)
    return {"blocks": [item for _, item in sorted(projected, key=lambda pair: pair[0])],
            "supports": [supports[i] for i in support_order],
            "rendered_originals": originals, "input_tokens": integer(value["input_tokens"]),
            "count_kind": enum(value["count_kind"], {"exact", "conservative_upper_bound"}),
            "wire_bytes": integer(value["wire_bytes"]), "added_original_bytes": integer(value["added_original_bytes"]),
            "usage": numeric(value["usage"], USAGE)}


def project(input_value):
    """Pure one-callback state/question projection, shared with future inference."""
    bounded_tree(input_value)
    shape(input_value, {"format", "base", "selected", "trial", "seed_slots", "closure_slots", "budget"})
    require(input_value["format"] == FEATURE_FORMAT, "conditional compiler schema")
    base = input_value["base"]
    shape(base, {"control", "working", "hot", "current"})
    messages, calls = [], set()
    for zone in ("control", "working", "hot", "current"):
        for message in array(base[zone], 128):
            shape(message, {"zone", "role", "text", "tool_calls", "tool_result"})
            slots = array(message["tool_calls"], 64)
            require(all(type(s) is int and s >= 0 and s not in calls for s in slots)
                    and len(slots) == len(set(slots)), "invalid tool call correspondence")
            calls.update(slots)
            result = message["tool_result"]
            require(result is None or type(result) is int and result in calls, "orphan tool result")
            messages.append({"zone": enum(message["zone"], ZONES), "role": enum(message["role"], ROLES),
                             "text": text(message["text"]), "tool_calls": slots, "tool_result": result})
    # Rebind call numbers to natural protocol order, never external call identity.
    call_slots = {old: new for new, old in enumerate(s for m in messages for s in m["tool_calls"])}
    for message in messages:
        message["tool_calls"] = [call_slots[s] for s in message["tool_calls"]]
        if message["tool_result"] is not None:
            message["tool_result"] = call_slots[message["tool_result"]]
    budget = input_value["budget"]
    shape(budget, VOLATILE | {"memory", "outgoing", "exact_marginal_input_tokens", "outgoing_fits"})
    for field in VOLATILE:
        integer(budget[field])
    memory = numeric(budget["memory"], MEMORY)
    outgoing = numeric(budget["outgoing"], OUTGOING)
    # Search/time allowances enforce execution outside the learned semantic record.
    memory.pop("max_selection_evaluations")
    delta = budget["exact_marginal_input_tokens"]
    if delta is not None:
        integer(delta, minimum=-(1 << 63))
    require(type(budget["outgoing_fits"]) is bool, "dispatch-fit flag")
    seeds = input_value["seed_slots"]
    require(type(seeds) is list and seeds, "actual optional proposal required")
    state = {"profile": PROJECTION, "base": messages, "selected": _assembly(input_value["selected"]),
             "memory_limits": memory, "outgoing_limits": outgoing}
    question = {"trial": _assembly(input_value["trial"], seeds, input_value["closure_slots"]),
                "exact_marginal_input_tokens": delta, "outgoing_fits": budget["outgoing_fits"]}
    state_text = bounded_canonical(state, LIMITS["state_bytes"]).decode("utf-8")
    branch = bounded_canonical(question, LIMITS["branch_bytes"]).decode("utf-8")
    return state_text, {"instr": "Does this proposed rendered closure add useful context beyond the selected base? " + branch,
                        "options": ["Useful", "Not useful"], "label": 0}


def group_example(key, rows):
    """Join independent masks after input-only ordering; all-zero is supervised."""
    require(0 < len(rows) <= LIMITS["questions"], "whole selected-base group ceiling")
    require(all(row[0] == rows[0][0] for row in rows), "selected-base semantics/capacity mismatch")
    require(all(row[2] is None or type(row[2]) is bool for row in rows), "conditional mask type")
    rows = sorted(rows, key=lambda row: canonical(row[1]))
    known = [row[2] is not None for row in rows]
    if not any(known):
        return None
    association = hashlib.sha256(canonical(key)).hexdigest()
    return Example(association, key[1], {"state": rows[0][0], "questions": [row[1] for row in rows]},
                   [float(row[2] is True) for row in rows], known,
                   ["bundle" if row[4] else "candidate" for row in rows])


def load_examples(corpus, seed=20261009):
    """Only a cold-verified fixed public artifact is admitted, never a grant."""
    require(set(PINS) == ARTIFACTS and re.fullmatch(r"[a-f0-9]{64}", CORPUS_BLAKE3),
            "conditional public corpus pins are not installed")
    root = checked_root(corpus)
    fixed_entries(root, ARTIFACTS)
    paths = {name: root / name for name in ARTIFACTS}
    require(all(path.is_file() and not path.is_symlink() and path.resolve() == path for path in paths.values()),
            "direct regular conditional artifacts required")
    sizes = {name: path.stat().st_size for name, path in paths.items()}
    require(sizes == FILE_BYTES and all(0 < size <= LIMITS["file_bytes"] for size in sizes.values())
            and sum(sizes.values()) <= LIMITS["corpus_bytes"], "joint corpus ceiling")
    for name, expected in PINS.items():
        require(sha_file(root / name, sizes[name]) == expected, "only fixed public conditional corpus is supported")
    manifest = read_json(root / "manifest.json", LIMITS["file_bytes"])
    shape(manifest, {"format", "profile", "builder", "generator", "cases", "rows", "artifacts"})
    require((manifest["format"], manifest["profile"], manifest["builder"], manifest["generator"]) ==
            (FORMAT, PROFILE, BUILDER, GENERATOR), "conditional corpus profile differs")
    integer(manifest["rows"], LIMITS["callbacks"], 1)
    integer(manifest["cases"], 64, 1)
    require(set(manifest["artifacts"]) == ARTIFACTS - {"manifest.json"}, "conditional artifact inventory")
    for name, item in manifest["artifacts"].items():
        shape(item, {"bytes", "digest"})
        require(item["bytes"] == sizes[name], "conditional artifact size association")
        require(type(item["digest"]) is str and re.fullmatch(r"[a-f0-9]{64}", item["digest"]), "artifact digest")
    inputs = read_json(root / "inputs.json", LIMITS["file_bytes"])
    observations = read_json(root / "observations.json", LIMITS["file_bytes"])
    targets = read_json(root / "targets.json", LIMITS["file_bytes"])
    lineage = read_json(root / "lineage.json", LIMITS["file_bytes"])
    shape(lineage, {"nodes", "cases", "split", "assignments"})
    array(lineage["nodes"], 8192)
    nodes = {canonical(node["reference"]): node for node in lineage["nodes"]}
    require(len(nodes) == len(lineage["nodes"]), "duplicate lineage reference")
    assignments = {a["example_id"]: a for a in lineage["assignments"]}
    cases = {a["example_id"]: a for a in lineage["cases"]}
    require(len(assignments) == len(lineage["assignments"]) == len(cases) == manifest["cases"], "complete case lineage")
    partitions = {p: set() for p in ("train", "validation", "test", "quarantined")}
    for case_id, assignment in assignments.items():
        shape(assignment, {"example_id", "group_digest", "partition", "window_start", "window_end"})
        partitions[enum(assignment["partition"], partitions)].add(assignment["group_digest"])
        require(case_id in cases, "missing case lineage")
    require(all(not a & b for i, a in enumerate(partitions.values()) for b in list(partitions.values())[i + 1:]),
            "source/history lineage split overlap")
    maps = []
    for rows in (inputs, observations, targets):
        array(rows, LIMITS["callbacks"])
        mapped = {row["row_id"]: row for row in rows}
        require(len(rows) == len(mapped) == manifest["rows"], "duplicate/incomplete callbacks")
        maps.append(mapped)
    source, observations, targets = maps
    require(source.keys() == observations.keys() == targets.keys(), "callback inventories differ")
    grouped = defaultdict(list)
    excluded = 0
    case_partitions = {p: sum(a["partition"] == p for a in assignments.values()) for p in partitions}
    callback_partitions = {p: 0 for p in partitions}
    for row_id, row in source.items():
        shape(row, {"row_id", "input"})
        text(row_id, 256)
        observation, target = observations[row_id], targets[row_id]
        shape(observation, {"row_id", "case_id", "logical_domain", "known_at", "evaluation", "feature_digest",
                            "request_digest", "selected_base_digest", "trial_wire_digest", "seed_ids", "closure_ids",
                            "selected_origins", "trial_origins", "selected", "trial", "outgoing_fits"})
        case_id = observation["case_id"]
        require(case_id in assignments, "callback has no history assignment")
        partition = assignments[case_id]["partition"]
        callback_partitions[partition] += 1
        if partition not in {"train", "validation"}:
            excluded += 1
            continue  # No projection, tokenization, model evaluation or optimization.
        require(observation["known_at"] == cases[case_id]["cutoff"] and
                observation["logical_domain"] == cases[case_id]["logical_domain"], "callback cutoff association")
        for field in ("feature_digest", "selected_base_digest", "trial_wire_digest"):
            require(target[field] == observation[field] and type(target[field]) is str
                    and re.fullmatch(r"[a-f0-9]{64}", target[field]), "target callback commitment differs")
        shape(target, {"row_id", "evaluation", "feature_digest", "selected_base_digest", "trial_wire_digest",
                       "useful", "reason", "provenance"})
        require(integer(target["evaluation"], (1 << 32) - 1) == observation["evaluation"],
                "target callback evaluation differs")
        useful = target["useful"]
        require(useful is None or type(useful) is bool, "conditional target type")
        reasons = {True: {"required_coverage_gain"}, False: {"already_sufficient", "no_required_coverage_gain"},
                   None: {"partial_required_coverage", "unresolved_task", "non_dispatchable_trial"}}
        enum(target["reason"], reasons[useful])
        require(type(observation["outgoing_fits"]) is bool and
                observation["outgoing_fits"] == row["input"]["budget"]["outgoing_fits"] and
                (observation["outgoing_fits"] or useful is None), "non-dispatchable utility must be unknown")
        provenance = target["provenance"]
        if useful is not None:
            shape(provenance, {"kind", "evaluator_version", "available_at", "logical_domain", "source_nodes"})
            require(provenance["kind"] == "synthetic_source_set" and
                    provenance["evaluator_version"] == "synthetic-conditional-source-coverage.v1" and
                    provenance["available_at"] == observation["known_at"] + 1 and
                    provenance["logical_domain"] == observation["logical_domain"], "conditional label provenance/cutoff")
            evaluation = canonical({"kind": "evaluation", "domain": observation["logical_domain"],
                                    "id": "source-label:" + case_id, "version": "v1"})
            require(evaluation in nodes and nodes[evaluation]["available_at"] == provenance["available_at"],
                    "exact label annotation lineage missing")
            roots = {canonical(ref) for ref in array(cases[case_id]["roots"], 256)}
            provenance_roots = array(provenance["source_nodes"], 256)
            require({canonical(ref) for ref in provenance_roots} == roots
                    and len(provenance_roots) == len(roots)
                    and {canonical(ref) for ref in nodes[evaluation]["parents"]} == roots,
                    "label source lineage association")
        else:
            require(provenance is None, "unknown utility must not fabricate known-label provenance")
        pending = list(cases[case_id]["roots"])
        seen = set()
        while pending:
            ref = pending.pop()
            encoded = canonical(ref)
            if encoded in seen:
                continue
            seen.add(encoded)
            require(encoded in nodes and len(seen) <= 8192, "missing query lineage")
            node = nodes[encoded]
            require(node["available_at"] <= observation["known_at"], "future source in query-time lineage")
            pending.extend(array(node["parents"], 256))
        key = case_id, partition, observation["selected_base_digest"]
        require(len(grouped[key]) < LIMITS["questions"], "whole selected-base proposal group exceeds ceiling")
        state, question = project(row["input"])
        grouped[key].append((state, question, useful, row_id, len(row["input"]["seed_slots"]) > 1))
    examples, unsupervised = [], 0
    counts = {p: 0 for p in ("train", "validation")}
    for key, rows in sorted(grouped.items()):
        example = group_example(key, rows)
        if example is None:
            unsupervised += 1
            continue
        examples.append(example)
        counts[key[1]] += 1
        require(counts[key[1]] <= LIMITS["groups_per_fold"], "supervised fold group ceiling")
    require(all(counts.values()), "train/development supervision absent")
    report = {"profile": PROFILE, "projection": PROJECTION, "corpus_manifest_blake3": CORPUS_BLAKE3,
                      "corpus_files_sha256": PINS, "partitions": counts, "excluded_model_examples": excluded,
                      "case_partitions": case_partitions, "callback_partitions": callback_partitions,
                      "unsupervised_groups": unsupervised, "limits": LIMITS, "unavailable": UNAVAILABLE,
                      "label_semantics": "conditional synthetic source-coverage surrogate; not measured reader utility"}
    require(all(report[key] == value for key, value in EXPECTED.items()), "fixed conditional population differs")
    return examples, report


def validate_saved_profile(profile, steps):
    require(profile["projection"] == PROJECTION and profile["corpus_manifest_blake3"] == CORPUS_BLAKE3
            and profile["corpus_files_sha256"] == PINS and profile["limits"] == LIMITS,
            "saved conditional corpus/projection differs")
    counts = profile["partitions"]
    shape(counts, {"train", "validation"})
    require(all(type(v) is int and 0 < v <= LIMITS["groups_per_fold"] for v in counts.values())
            and profile["epochs"] == 1 and steps == counts["train"], "bounded conditional optimization profile")
    require(EXPECTED and all(profile[key] == value for key, value in EXPECTED.items()),
            "saved conditional population differs")
