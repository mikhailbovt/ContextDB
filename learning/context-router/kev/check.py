"""Meaningful pure data gates. Does not import torch, tokenize or call a model."""
import copy
import argparse
import json
import tempfile
import sys
from pathlib import Path

from corpus import (LIMITS, attach_labels, canonical, checked_root, input_projection,
                    load_examples, read_json, require, sha_file)
from trainer import (BUNDLE_FORMAT, BUNDLE_LIMITS, BUNDLE_MAX_BYTES,
                     PROFILE, inspect_bundle, publish_bundle, run_path, validate_lock)


def reject(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("expected bounded refusal")


def conditional_checks(corpus):
    import conditional as data
    examples, report = data.load_examples(corpus)
    require(examples and all(e.partition in {"train", "validation"} for e in examples), "conditional held-out exclusion")
    require(any(any(e.known) and not any(y for y, k in zip(e.labels, e.known) if k) for e in examples),
            "known all-zero conditional group absent")
    require(any(y and k and kind == "bundle" for e in examples for y, k, kind in zip(e.labels, e.known, e.kinds)),
            "actual complementary closure supervision absent")
    require(any(sum(y == 1 and k and kind == "candidate" for y, k, kind in zip(e.labels, e.known, e.kinds)) >= 2
                for e in examples), "actual conditional independent multi-positive candidates absent")
    require(any(not k for e in examples for k in e.known), "partial unknown masks absent")
    lineage = read_json(corpus / "lineage.json", data.LIMITS["file_bytes"])
    assignments = {a["example_id"]: a["partition"] for a in lineage["assignments"]}
    observations = {o["row_id"]: o for o in read_json(corpus / "observations.json", data.LIMITS["file_bytes"])}
    rows = read_json(corpus / "inputs.json", data.LIMITS["file_bytes"])
    row = next(r for r in rows if assignments[observations[r["row_id"]]["case_id"]] == "train")
    value = row["input"]
    state, question = data.project(value)
    original = canonical((state, question))
    changed = copy.deepcopy(value)
    for key in data.VOLATILE:
        changed["budget"][key] += 1
    for assembly in (changed["selected"], changed["trial"]):
        for block in assembly["blocks"]:
            if block["alternative_index"] is not None:
                block["alternative_index"] += 1
    require(canonical(data.project(changed)) == original, "execution/alternative ordinals escaped projection")
    # Only unordered inventories are permuted. Conversation/source chronology is preserved.
    reordered = copy.deepcopy(value)
    for name in ("selected", "trial"):
        assembly = reordered[name]
        count = len(assembly["supports"])
        assembly["supports"].reverse()
        for block in assembly["blocks"]:
            block["support_slots"] = [count - 1 - h for h in block["support_slots"]]
        block_count = len(assembly["blocks"])
        assembly["blocks"].reverse()
        if name == "trial":
            for field in ("seed_slots", "closure_slots"):
                reordered[field] = [block_count - 1 - h for h in reordered[field]]
    for zone in reordered["base"].values():
        for message in zone:
            message["tool_calls"] = [slot + 100 for slot in message["tool_calls"]]
            if message["tool_result"] is not None:
                message["tool_result"] += 100
    require(canonical(data.project(reordered)) == original, "local inventory/call renaming changed semantics")
    duplicate = copy.deepcopy(value)
    if duplicate["trial"]["supports"]:
        duplicate["trial"]["supports"].append(copy.deepcopy(duplicate["trial"]["supports"][0]))
        first = canonical(data.project(duplicate))
        a = duplicate["trial"]
        last = len(a["supports"]) - 1
        a["supports"][0], a["supports"][last] = a["supports"][last], a["supports"][0]
        for block in a["blocks"]:
            block["support_slots"] = [last if h == 0 else 0 if h == last else h for h in block["support_slots"]]
        require(canonical(data.project(duplicate)) == first, "equal-support identity leaked")
    key = ("opaque-host-case", "train", "opaque-selected-commitment")
    proposed = [(state, question, True, "host-row-a", False), (state, question, None, "host-row-b", True)]
    example = data.group_example(key, proposed)
    mutated = [(s, q, False if y is not None else None, host, bundle) for s, q, y, host, bundle in proposed]
    different = data.group_example(key, mutated)
    require(example.record == different.record and example.labels != different.labels and
            example.known == different.known and example.known == [True, False], "labels/masks entered model input")
    require(not any(different.labels) and any(different.known), "all-zero known group rejected")
    require(data.group_example(key, [(state, question, None, "host-row", False)]) is None,
            "unknown became a negative")
    reject(lambda: data.group_example(key, proposed * 9))
    injection = copy.deepcopy(value)
    injection["behavior"] = {"score": 999, "gold": "answer"}
    reject(lambda: data.project(injection))
    natural_row = next(r for r in rows if assignments[observations[r["row_id"]]["case_id"]] == "train"
                       and any(b["kind"] != "raw_observation" for b in r["input"]["trial"]["blocks"]))
    bad = copy.deepcopy(natural_row["input"])
    nonraw = next(b for b in bad["trial"]["blocks"] if b["kind"] != "raw_observation")
    nonraw["representation"]["fields"]["resolution"] = "private-claim-ID"
    reject(lambda: data.project(bad))
    too_large = copy.deepcopy(value)
    too_large["base"]["current"][0]["text"] = "x" * (data.LIMITS["input_bytes"] + 1)
    reject(lambda: data.project(too_large))
    # The initial-context bundle is rejected before artifact hashes/tensor construction.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        bundle = root / "old-bundle"
        bundle.mkdir()
        manifest = {"format": BUNDLE_FORMAT, "profile": PROFILE, "optimizer_steps": 8,
                    "trainable_tensors_sha256": "0" * 64, "useful_model_claim": False,
                    "current_training_grant": False, "files": {}}
        (bundle / "bundle.json").write_bytes(canonical(manifest))
        reject(lambda: inspect_bundle(bundle, root, profile_name=data.PROFILE))
    print(json.dumps({"status": "conditional-pure-gates-passed", "intake": report,
                      "test_model_use": 0, "quarantine_model_use": 0, "no_model_import": True,
                      "grouped_gates": ["actual-closure-label-and-order-isolation", "conditional-independent-known-masks",
                                        "strict-intake-projection-and-bundle-compatibility"]}))


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--corpus", type=Path, required=True)
parser.add_argument("--profile", choices=("initial-context", "rendered-closure"), default="initial-context")
args = parser.parse_args()
corpus = checked_root(args.corpus)
if args.profile == "rendered-closure":
    conditional_checks(corpus)
    sys.exit(0)
examples, report = load_examples(corpus)
require(len(examples) == 16 and all(x.partition in {"train", "validation"} for x in examples), "held-out exclusion")
require(sum(x.partition == "train" for x in examples) == 8, "train count")
require(sum(x.partition == "validation" for x in examples) == 8, "dev count")
require(any(sum(y for y, k in zip(x.labels, x.known) if k) == 0 for x in examples), "all-zero supervision missing")
require(any(sum(y for y, k, t in zip(x.labels, x.known, x.kinds) if k and t == "candidate") > 1
            for x in examples), "independent multiple-positive candidates missing")
require(any(y == 1 and k and t == "bundle" for x in examples
            for y, k, t in zip(x.labels, x.known, x.kinds)), "positive complement supervision missing")
require(not any(y == 0 and k and t == "bundle" for x in examples
                for y, k, t in zip(x.labels, x.known, x.kinds)), "prototype invented bundle negatives")

rows = read_json(corpus / "features.json")
targets = {x["example_id"]: x for x in read_json(corpus / "targets.json")}
feature = rows[0]["features"]
record, proposals = input_projection(feature, 42)
renamed = copy.deepcopy(feature)
ids = {c["id"]: f"opaque-key-{i}" for i, c in enumerate(renamed["candidates"])}
handles = {e["id"]: f"opaque-support-{i}" for i, e in enumerate(renamed["evidence"])}
for candidate in renamed["candidates"]:
    candidate["id"] = ids[candidate["id"]]
    for representation in candidate["representations"]:
        representation["summary"] = "SHOULD-NOT-APPEAR hidden-fixture-ID"
    for support in candidate["support_alternatives"]:
        support["evidence_handles"] = [handles[h] for h in support["evidence_handles"]]
        support["hard_closure"] = [ids[h] for h in support["hard_closure"]]
for evidence in renamed["evidence"]:
    evidence["id"] = handles[evidence["id"]]
    evidence["source"] = "SHOULD-NOT-APPEAR source-address"
renamed["query"]["id"] = "SHOULD-NOT-APPEAR example-ID"
renamed["query"]["scope"] = "SHOULD-NOT-APPEAR scope"
renamed["candidates"].reverse()
renamed["evidence"].reverse()
renamed_record, _ = input_projection(renamed, 42)
require(canonical(record) == canonical(renamed_record), "ID renaming/storage ordering changed semantic input")

target = targets[feature["query"]["id"]]
mutated_target = copy.deepcopy(target)
for item in mutated_target["candidates"]:
    if item["useful"] is not None:
        item["useful"] = not item["useful"]
changed_labels = attach_labels(feature, mutated_target, proposals)
require(changed_labels != attach_labels(feature, target, proposals), "label mutation did not affect supervision")
require(canonical(input_projection(feature, 42)[0]) == canonical(record), "label/evaluator mutation changed features")
require(all(q["label"] == 0 for q in record["questions"]), "upstream dummy labels expose supervision")
require(sum(kind == "bundle" for kind, _ in proposals) == 3, "all input pairs not enumerated")
labels, known, kinds = attach_labels(feature, target, proposals)
require(all(not k for k, t in zip(known, kinds) if t == "bundle"), "unobserved pairs became negatives")
complement = next(x for x in rows if x["features"]["query"]["id"] == "group-0-Complement")["features"]
_, proposals = input_projection(complement, 77)
y, known, kinds = attach_labels(complement, targets[complement["query"]["id"]], proposals)
require(sum(k and label == 1 and kind == "bundle" for label, k, kind in zip(y, known, kinds)) == 1,
        "complement positive bundle missing")
require(sum(k for k, kind in zip(known, kinds) if kind == "candidate") == 1,
        "unknown individual complements must stay masked")

unsupported = copy.deepcopy(feature)
unsupported["candidates"][0]["hard_dependencies"] = [unsupported["candidates"][1]["id"]]
reject(lambda: input_projection(unsupported, 42))
oversized = copy.deepcopy(feature)
oversized["query"]["query"] = "x" * (LIMITS["state_bytes"] + 1)
reject(lambda: input_projection(oversized, 42))
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory).resolve()
    path = root / "large.json"
    path.write_bytes(b"x" * 1024)
    reject(lambda: sha_file(path, 100))
    reject(lambda: read_json(path, 100))
    reject(lambda: run_path(root, "../escape"))
    reject(lambda: run_path(root, "com1"))
    staging = root / "publish.partial"
    staging.mkdir()
    (staging / "payload").write_bytes(b"retained")
    output = run_path(root, "published")
    publish_bundle(staging, output)
    require((output / "payload").read_bytes() == b"retained", "atomic publication lost material")
    staging.mkdir()
    reject(lambda: publish_bundle(staging, output))
    require(staging.is_dir() and (output / "payload").read_bytes() == b"retained", "existing output overwritten")
    lock = read_json(Path(__file__).with_name("model-lock.example.json"), 64 << 10)
    lock["paths"] = {name: str(root) for name in ("source", "adapter", "base")}
    validate_lock(lock)
    changed = copy.deepcopy(lock)
    changed["components"]["adapter"]["revision"] = "0" * 40
    reject(lambda: validate_lock(changed))
    changed = copy.deepcopy(lock)
    changed["components"]["base"]["files"]["config.json"]["bytes"] = 1 << 50
    reject(lambda: validate_lock(changed))
    changed = copy.deepcopy(lock)
    changed["paths"]["source"] = "relative/path"
    reject(lambda: validate_lock(changed))
    bundle = root / "bundle"
    bundle.mkdir()
    manifest = {"format": BUNDLE_FORMAT, "profile": PROFILE, "optimizer_steps": 8,
                "trainable_tensors_sha256": "0" * 64, "useful_model_claim": False,
                "current_training_grant": False,
                "files": {name: {"bytes": 1, "sha256": "0" * 64} for name in BUNDLE_LIMITS}}
    manifest["files"]["adapter.safetensors"]["bytes"] = BUNDLE_LIMITS["adapter.safetensors"] + 1
    (bundle / "bundle.json").write_bytes(canonical(manifest))
    reject(lambda: inspect_bundle(bundle, root))  # Refuses before any tensor/file hash.
    manifest["files"] = {name: {"bytes": cap, "sha256": "0" * 64} for name, cap in BUNDLE_LIMITS.items()}
    require(sum(v["bytes"] for v in manifest["files"].values()) > BUNDLE_MAX_BYTES, "sum fault fixture")
    (bundle / "bundle.json").write_bytes(canonical(manifest))
    reject(lambda: inspect_bundle(bundle, root))
    duplicate = root / "duplicate.json"
    duplicate.write_text('{"key":1,"key":2}', encoding="utf-8")
    reject(lambda: read_json(duplicate))
print(json.dumps({"status": "pure-formatter-mask-bound-gates-passed", "train": 8, "dev": 8,
                  "test_model_use": 0, "quarantine_model_use": 0, "no_model_import": True,
                  "grouped_gates": ["input-identity-order-and-label-isolation", "independent-and-bundle-masks",
                                    "strict-profile-lock-and-prehash-bundle-bounds"]}))
