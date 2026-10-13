"""Pinned public synthetic intake and an explicit semantic whitelist; no model imports."""
from __future__ import annotations

import hashlib
import itertools
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path

PROFILE = "contextdb.kev-public-synthetic-initial-context-bce.v1"
CORPUS_BLAKE3 = "a6d856160f964b8905d943acc75a38aa6a2d1c9b4ba8adfc35428a3b21c026ab"
PINS = {
    "behavior.json": "6af8f6face5345f467e6e422505bddf0cae12afddc7341a1b1af9f33e736aa87",
    "features.json": "c5ac4e624fee146b9c539d2a35b69f1169abccb723036260813c248f63e7f460",
    "lineage.json": "73853e8bd10082902fdb855d8d7ef1cac3d755ffd382e93ab17ea7d806019e76",
    "manifest.json": "33493b8bcb9356a7aad24e4ec1d2b31972586d36baf9bad29b82880a49f749ed",
    "query-time.json": "c72df4e03d0d8a4163c887e7d3ebf9ca9bca153f324b1fb649a2ea367c6074a5",
    "targets.json": "8a0c7719a9d7a243f91fa2d95094d9cae3ee251bf70097507d64810a11de4612",
}
LIMITS = {"file_bytes": 8 << 20, "state_bytes": 12000, "branch_bytes": 12000,
          "optional_candidates": 4, "questions": 10, "state_tokens": 384,
          "row_tokens": 1024, "packed_tokens": 4096}
UNAVAILABLE = ["compiler_selected_base_scoring_unit", "intermediate_trial_semantic_view",
               "current_native_source_wire", "private_training_export_admission",
               "calibrated_marginal_utility", "generalization_and_reader_benefit"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha_file(path: Path, maximum: int | None = None) -> str:
    require(path.is_file() and not path.is_symlink(), "regular hash input required")
    if maximum is not None:
        require(path.stat().st_size <= maximum, "hash input exceeds admitted bound")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(4 << 20), b""):
            h.update(part)
    return h.hexdigest()


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path, maximum: int = LIMITS["file_bytes"]):
    require(path.is_file() and not path.is_symlink(), "regular input file required")
    require(path.stat().st_size <= maximum, "input file exceeds profile")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def bounded_text(value, maximum=12000):
    require(isinstance(value, str) and len(value.encode("utf-8")) <= maximum,
            "unsupported or oversized semantic text; truncation is forbidden")
    return value


@dataclass
class Example:
    # Association metadata stays outside the record supplied to the model.
    association: str
    partition: str
    record: dict
    labels: list[float]
    known: list[bool]
    kinds: list[str]


def input_projection(feature: dict, order_seed: int) -> tuple[dict, list[tuple[str, object]]]:
    """Build proposals solely from query-time input; never receives labels or behavior."""
    require(feature["schema"] == "contextdb.router-features.semantic-input.v1", "feature schema")
    candidates = feature["candidates"]
    require(len(candidates) <= 5, "unsupported candidate inventory")
    by_id = {c["id"]: c for c in candidates}
    require(len(by_id) == len(candidates), "duplicate candidate")
    evidence = {e["id"]: e for e in feature["evidence"]}
    require(len(evidence) == len(feature["evidence"]), "duplicate evidence")
    optional = [c for c in candidates if not c["mandatory"]]
    require(0 < len(optional) <= LIMITS["optional_candidates"], "unsupported optional count")
    # Random ranks attach to input order only; no label/scenario/ID-derived RNG seed.
    def semantic_order(c):
        # Canonicalize source semantics before permutation; storage/UUID ordering
        # does not become an implicit slot feature.
        return canonical({"texts": [[evidence[h]["excerpt"] for h in s["evidence_handles"]]
                                    for s in c["support_alternatives"]],
                          "speaker": [r["fields"].get("speaker") for r in c["representations"]],
                          "age": feature["query"]["known_at"] - c["known_at_commit"]})
    optional.sort(key=semantic_order)
    rng = random.Random(order_seed)
    rng.shuffle(optional)
    slot = {c["id"]: f"Memory {i + 1}" for i, c in enumerate(optional)}
    mandatory = [c for c in candidates if c["mandatory"]]
    require(all(c["kind"] == "situation" for c in mandatory),
            "prototype supports only query Situation mandatory context")
    require(all(not c["hard_dependencies"] and not c["complements"] for c in candidates),
            "linked closure semantic material unsupported by this initial prototype")

    def candidate(c):
        require(c["kind"] == "raw_observation", "unsupported synthetic candidate kind")
        require(c["known_at_commit"] <= feature["query"]["known_at"], "future candidate")
        alternatives = []
        for support in c["support_alternatives"]:
            excerpts = []
            for handle in support["evidence_handles"]:
                require(handle in evidence, "missing support")
                item = evidence[handle]
                require(item["original_span"] is not None, "attributed support required")
                require(item["source_class"] in {"user_statement", "model_generated"}, "unsupported source class")
                excerpts.append({"text": bounded_text(item["excerpt"]),
                                 "source_class": item["source_class"],
                                 "trust": item["trust_micros"] / 1000000,
                                 "primary": item["primary"]})
            alternatives.append({"level": support["level"], "evidence": excerpts})
        require(alternatives and all(a["evidence"] for a in alternatives), "empty raw support")
        require(c["source_class"] in {"user_statement", "model_generated"} and
                c["interpretation"] == "historical_data" and c["trust"] == "untrusted",
                "unsupported raw semantic profile")
        speakers = {r["fields"].get("speaker") for r in c["representations"]}
        require(speakers <= {"user", "assistant", "tool", "system"}, "unsupported speaker")
        for dependency in c["hard_dependencies"] + c["complements"]:
            require(dependency in slot or dependency in {m["id"] for m in mandatory},
                    "missing dependency")
        # Raw representation summaries name synthetic IDs; do not render them.
        # No source names, UUIDs, scopes, hashes or absolute compiler counters enter.
        return {"slot": slot[c["id"]], "kind": c["kind"], "speakers": sorted(speakers),
                "source_class": c["source_class"], "interpretation": c["interpretation"],
                "trust": c["trust"], "known_age": feature["query"]["known_at"] - c["known_at_commit"],
                "support_alternatives": alternatives,
                "hard_dependencies": sorted(slot[d] for d in c["hard_dependencies"] if d in slot),
                "complements": sorted(slot[d] for d in c["complements"] if d in slot)}

    conversation = []
    for zone in ("control", "working", "hot", "current"):
        for message in feature["base"].get(zone, []):
            require(not message["tool_calls"] and message["tool_result"] is None,
                    "tool semantic protocol unsupported in this prototype")
            conversation.append({"zone": zone, "role": message["role"],
                                 "text": bounded_text(message["text"])})
    state = {"query": bounded_text(feature["query"]["query"]), "conversation": conversation,
             "mandatory_context": "The required Situation repeats the current query; it adds no fact.",
             "base_profile": "initial query-time mandatory context, no selected optional memories",
             "input_limit_tokens": feature["outgoing_budget"]["max_input_tokens"],
             "memory_limit_tokens": feature["memory_budget"]["hard_tokens"]}
    state_text = canonical(state).decode("utf-8")
    require(len(state_text.encode("utf-8")) <= LIMITS["state_bytes"], "state byte ceiling")
    questions, proposals = [], []
    payload = {c["id"]: candidate(c) for c in optional}
    for c in optional:
        proposals.append(("candidate", c["id"]))
        text = "Does this optional memory help the current query beyond the initial context? " + canonical(payload[c["id"]]).decode("utf-8")
        questions.append({"instr": bounded_text(text), "options": ["Useful", "Not useful"], "label": 0})
    # Every pair is proposed from inputs, never from target gold bundle membership.
    pairs = list(itertools.combinations([c["id"] for c in optional], 2))
    rng.shuffle(pairs)
    for number, pair in enumerate(pairs, 1):
        proposals.append(("bundle", frozenset(pair)))
        members = [payload[member] for member in pair]
        text = "Does selecting this memory union help the current query beyond the initial context? " + canonical({"slot": f"Bundle {number}", "members": members}).decode("utf-8")
        questions.append({"instr": bounded_text(text), "options": ["Useful", "Not useful"], "label": 0})
    require(len(questions) <= LIMITS["questions"], "question ceiling")
    record = {"state": state_text, "questions": questions}
    rendered = canonical(record).decode("utf-8")
    require(not re.search(r"group-\d|synthetic:|raw:|evidence:|[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-", rendered),
            "association metadata escaped semantic whitelist")
    return record, proposals


def attach_labels(feature, target, proposals):
    require(target["format"] == "contextdb.router-utility-targets.v1", "target schema")
    candidates = {c["id"]: c for c in feature["candidates"]}
    targets = {t["candidate_id"]: t for t in target["candidates"]}
    require(set(candidates) == set(targets), "target inventory differs")
    for candidate_id, c in candidates.items():
        if c["mandatory"] or c["kind"] == "unknown":
            require(targets[candidate_id]["useful"] is None, "mandatory/Unknown must be masked")
    bundles = {}
    for item in target["bundles"]:
        members = frozenset(item["members"])
        require(len(members) == len(item["members"]) == 2 and members <= candidates.keys(),
                "unsupported bundle membership")
        require(members not in bundles, "duplicate bundle target")
        bundles[members] = item
    labels, known, kinds = [], [], []
    for kind, identity in proposals:
        item = targets[identity] if kind == "candidate" else bundles.get(identity)
        useful = None if item is None else item["useful"]
        require(useful is None or type(useful) is bool, "invalid utility target")
        if useful is not None:
            p = item["provenance"]
            require(p and p["kind"] == "synthetic_source_set" and
                    p["evaluator_version"] == "synthetic-source-set.v1", "unsupported label provenance")
        labels.append(float(useful is True))
        known.append(useful is not None)
        kinds.append(kind)
    require(any(known), "zero-supervision example")
    return labels, known, kinds


def checked_root(value: str | Path) -> Path:
    root = Path(value)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink()
            and root.resolve() == root, "absolute resolved non-symlink directory required")
    return root


def fixed_entries(root: Path, expected: set[str]) -> None:
    names = set()
    for entry in root.iterdir():
        require(entry.name in expected and len(names) < len(expected),
                "unexpected directory entry")
        names.add(entry.name)
    require(names == expected, "directory entries differ")


def load_examples(corpus: str | Path, seed=20261009):
    corpus = checked_root(corpus)
    # Exact public artifact bytes are the intake allowlist, not training rights.
    fixed_entries(corpus, set(PINS))
    for filename, digest in PINS.items():
        require(sha_file(corpus / filename, LIMITS["file_bytes"]) == digest,
                "only the pinned public synthetic corpus is supported; private intake is unavailable")
    manifest = read_json(corpus / "manifest.json")
    require(manifest["format"] == "contextdb.router-corpus.synthetic-replay.v1" and manifest["examples"] == 32,
            "only cold-verified builtin replay profile is supported")
    features = read_json(corpus / "features.json")
    targets = {t["example_id"]: t for t in read_json(corpus / "targets.json")}
    behavior = {t["example_id"]: t for t in read_json(corpus / "behavior.json")}
    lineage = read_json(corpus / "lineage.json")
    assignments = {x["example_id"]: x for x in lineage["assignments"]}
    require(len(features) == len(targets) == len(behavior) == len(assignments) == 32, "complete 32 examples required")
    counts = {p: sum(x["partition"] == p for x in assignments.values())
              for p in ("train", "validation", "test", "quarantined")}
    require(all(v == 8 for v in counts.values()), "declared partitions changed")
    groups = {p: {x["group_digest"] for x in assignments.values() if x["partition"] == p} for p in counts}
    require(all(not groups[a] & groups[b] for a, b in itertools.combinations(groups, 2)), "split group overlap")
    examples = []
    for index, row in enumerate(features):
        feature = row["features"]
        association = feature["query"]["id"]
        partition = assignments[association]["partition"]
        if partition not in {"train", "validation"}:
            continue  # Neither rendered, encoded, optimized nor evaluated.
        target = targets[association]
        first_score = behavior[association]["plan"]["scores"][0]
        require(target["conditional_base_digest"] == first_score["selected_base_digest"], "label base association differs")
        require(all(row["material_verification"][s]["status"] == "verified"
                    for s in ("support_material", "unit_semantics", "candidate_commitment")), "unverified query-time material")
        record, proposals = input_projection(feature, seed + index)
        labels, known, kinds = attach_labels(feature, target, proposals)
        examples.append(Example(association, partition, record, labels, known, kinds))
    require(len(examples) == 16, "train/dev population changed")
    return examples, {"profile": PROFILE, "corpus_manifest_blake3": CORPUS_BLAKE3,
                      "corpus_files_sha256": PINS, "partitions": counts, "excluded_model_examples": 16,
                      "unavailable": UNAVAILABLE, "limits": LIMITS}
