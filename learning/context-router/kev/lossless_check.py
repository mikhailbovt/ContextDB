"""Three pure gates; import only the exact frozen stdlib-only normalizer."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

PINS = {
    "corpus.py": "a5402749e8e2b9ae06606f0e41ded051addf85957b1a3c34add76d934d86fc12",
    "trainer.py": "bb00cfa6ebfa2d956edc5262ceafdf497e881d8a048745479a47a238c31594cc",
    "check.py": "5a37ce05d39df1aca2c6db1ad8a51a2c057dddcc3007d960451959a70725df14",
    "conditional.py": "b3c24f5dfdda29465f4b5cc4d2d0a73a7d3ee44cb312ee2437f4cca57a910827",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def load(directory):
    directory = Path(directory)
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), "frozen directory")
    for name, expected in PINS.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1 << 20, "frozen source bound")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "frozen source mismatch")
    sys.path.insert(0, str(directory))
    sys.path.insert(1, str(Path(__file__).resolve().parent))
    import conditional
    import corpus
    import lossless as codec
    require(Path(conditional.__file__).resolve() == (directory / "conditional.py").resolve(), "normalizer import path")
    require(Path(corpus.__file__).resolve() == (directory / "corpus.py").resolve(), "intake import path")
    require(codec.v1 is conditional, "single normalizer")
    return conditional, codec


def fixture(v1):
    # Source prose deliberately contains a UUID; only metadata must be opaque-free.
    source = ("Observed code is amber42; retain this exact source, including UUID "
              "39c406a2-773c-4c73-a1c3-3ad091968b19 and Unicode: ёж. ") * 12
    other = "The second observed code is blue57 and requires the qualifying constraint."
    support = {"excerpt": source, "primary": True, "source_class": "user_statement", "original_bytes": len(source.encode())}

    def block(kind, summary, fields, supports, interpretation="factual_data"):
        return {"kind": kind, "representation": {"level": "l4_raw" if kind == "raw_observation" else "l2_structured",
                "summary": summary, "fields": fields, "omitted_facets": []},
                "exact_fragments": [{"label": "Observed literal", "value": source}],
                "epistemic": {"basis": "observation", "acceptance": "accepted", "conflict": {"state": "none"},
                              "lifecycle": "active"}, "interpretation": interpretation, "source_class": "user_statement",
                "support": {"state": "supported"}, "valid_time": {"start": -3, "end": 10}, "facets": [],
                "support_slots": supports, "use_action": "use_silently", "directive_reason": "mention_denied",
                "alternative_index": 7}

    raw = block("raw_observation", None, None, [0, 1])
    unknown = block("unknown", "The prerequisite remains unknown.", {"question": "Which prerequisite applies?"}, [],
                    "unknown_marker")
    unknown["support"] = {"state": "unsupported", "reason": "The prerequisite has no admitted proof."}
    unknown["unknown"] = {"question": "Which prerequisite applies?", "reason": "No observed answer.", "blocking": True}
    conflict = block("conflict", "Two observed codes remain unresolved.", {"reason": "Two observed codes remain unresolved."},
                     [0], "conflict_alternatives")
    conflict["conflict"] = {"blocking": True, "alternatives": 2, "resolved": False,
                            "rationale": "Preserve both observations until resolution."}
    conflict["epistemic"]["conflict"]["state"] = "in_conflict"

    def assembly(blocks, tokens):
        return {"blocks": blocks, "supports": [copy.deepcopy(support), copy.deepcopy(support)],
                "rendered_originals": [{"zone": "working_state", "role": "developer", "text": source},
                                       {"zone": "current_turn", "role": "user", "text": source},
                                       {"zone": "evidence", "role": "user", "text": source}],
                "input_tokens": tokens, "count_kind": "exact", "wire_bytes": 900 + tokens,
                "added_original_bytes": 32, "usage": {key: index + 1 for index, key in enumerate(sorted(v1.USAGE))}}

    def message(zone, role, text, calls=None, result=None):
        return {"zone": zone, "role": role, "text": text, "tool_calls": [] if calls is None else calls, "tool_result": result}

    return {"format": v1.FEATURE_FORMAT,
            "base": {"control": [message("control", "system", "Use observed source data.")],
                     "working": [message("working_state", "developer", source)],
                     "hot": [message("hot_history", "assistant", "Read the local note.", [71]),
                             message("hot_history", "tool", other, result=71)],
                     "current": [message("current_turn", "user", source)]},
            "selected": assembly([copy.deepcopy(raw)], 310),
            "trial": assembly([raw, unknown, conflict], 418), "seed_slots": [0, 2], "closure_slots": [0, 1, 2],
            "budget": {"memory": {key: 8192 for key in v1.MEMORY},
                       "outgoing": {"max_input_tokens": 8192, "safety_tokens": 32, "max_wire_bytes": 1 << 20},
                       **{key: 1000 for key in v1.VOLATILE}, "exact_marginal_input_tokens": 108, "outgoing_fits": True}}


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def branch(codec, question):
    return json.loads(question["instr"][len(codec.INSTRUCTION_PREFIX):])


def question(codec, value):
    return {"instr": codec.INSTRUCTION_PREFIX + wire(value), "options": list(codec.OPTIONS), "label": 0}


def refused(operation):
    try:
        operation()
    except ValueError:
        return
    raise ValueError("expected strict refusal")


def roundtrip(v1, codec, value):
    old = v1.project(value)
    new = codec.project(value)
    require(codec.expand(*new) == old, "exact normalized expansion")
    require(codec.project(value) == new, "deterministic codec")
    require(len(new[0].encode()) <= codec.MAX_BYTES, "state serialized cap")
    require(len(new[1]["instr"][len(codec.INSTRUCTION_PREFIX):].encode()) <= codec.MAX_BYTES, "trial serialized cap")
    return old, new


def equality_gate(v1, codec, value):
    old, new = roundtrip(v1, codec, value)
    require(len(new[0].encode()) + len(new[1]["instr"].encode()) < len(old[0].encode()) + len(old[1]["instr"].encode()),
            "repeated-payload fixture compression")
    restored_state = json.loads(codec.expand(*new)[0])
    restored_trial = branch(codec, codec.expand(*new)[1])["trial"]
    require(len(restored_state["base"]) == 5 and restored_state["base"][2]["tool_calls"] == [0]
            and restored_state["base"][3]["tool_result"] == 0, "base tool chronology")
    require(restored_trial["input_tokens"] == 418 and restored_trial["wire_bytes"] == 1318
            and sum(item["seed"] for item in restored_trial["blocks"]) == 2
            and sum(item["added_closure"] for item in restored_trial["blocks"]) == 3, "full trial and costs")
    require(any("unknown" in item for item in restored_trial["blocks"])
            and any("conflict" in item for item in restored_trial["blocks"]), "epistemic diagnostics")


def occurrence_gate(v1, codec, value):
    old, new = roundtrip(v1, codec, value)
    source = value["base"]["current"][0]["text"]
    table = json.loads(new[0])["texts"]
    require(table.count(source) == 1, "exact payload interned once")
    state = json.loads(codec.expand(*new)[0])
    selected = state["selected"]
    require([item["text"] for item in selected["rendered_originals"]] == [source] * 3
            and [item["zone"] for item in selected["rendered_originals"]] == ["working_state", "current_turn", "evidence"],
            "ordered equal-text occurrences preserved")
    require(len(selected["supports"]) == 2 and len(selected["blocks"][0]["supports"]) == 2,
            "equal support occurrences retained")
    changed = copy.deepcopy(value)
    text = "A new trial-only support replaces the earlier selected proof."
    changed["trial"]["supports"][0]["excerpt"] = text
    changed["trial"]["blocks"][0]["exact_fragments"][0]["value"] = text
    changed["trial"]["blocks"][0]["representation"]["level"] = "l3_evidence"
    changed["trial"]["usage"]["raw_evidence_tokens"] += 19
    changed_old, changed_new = roundtrip(v1, codec, changed)
    require(changed_new[0] == new[0] and text not in json.loads(changed_new[0])["texts"], "trial cannot pollute state")
    require(text in branch(codec, changed_new[1])["texts"] and changed_old[1] != old[1], "full changed trial retained")


def isolation_gate(v1, codec, value):
    _, new = roundtrip(v1, codec, value)
    reordered = copy.deepcopy(value)
    for name in ("selected", "trial"):
        assembly = reordered[name]
        support_count = len(assembly["supports"])
        assembly["supports"].reverse()
        for block in assembly["blocks"]:
            block["support_slots"] = [support_count - 1 - slot for slot in block["support_slots"]]
            block["alternative_index"] = 123
        block_count = len(assembly["blocks"])
        assembly["blocks"].reverse()
        if name == "trial":
            for key in ("seed_slots", "closure_slots"):
                reordered[key] = [block_count - 1 - slot for slot in reordered[key]]
    for key in v1.VOLATILE:
        reordered["budget"][key] += 200000
    reordered["budget"]["memory"]["max_selection_evaluations"] += 100
    require(codec.project(reordered) == new, "storage/order/ordinal/volatile invariance")
    for key in ("label", "gold", "prior", "score", "outcomes", "source_id"):
        mutated = copy.deepcopy(value)
        mutated[key] = "forbidden"
        refused(lambda: codec.project(mutated))
    for field in ("native_record", "resolution", "scope"):
        mutated = copy.deepcopy(value)
        mutated["trial"]["blocks"][1]["representation"]["fields"][field] = "opaque"
        refused(lambda: codec.project(mutated))
    mutated = copy.deepcopy(value)
    mutated["trial"]["blocks"][0]["representation"]["summary"] = "Original occurrence: hidden-id"
    refused(lambda: codec.project(mutated))
    state, trial = json.loads(new[0]), branch(codec, new[1])
    bad = copy.deepcopy(state)
    bad["record"]["gold"] = True
    refused(lambda: codec.expand(wire(bad), new[1]))
    bad = copy.deepcopy(state)
    bad["record"]["base"][0]["text"] = {"trial": 0}
    refused(lambda: codec.expand(wire(bad), new[1]))
    bad = copy.deepcopy(trial)
    bad["record"]["trial"]["supports"][0]["excerpt"] = {"state": True}
    refused(lambda: codec.expand(new[0], question(codec, bad)))
    bad = copy.deepcopy(state)
    bad["texts"].append(bad["texts"][0])
    refused(lambda: codec.expand(wire(bad), new[1]))
    bad = copy.deepcopy(trial)
    bad["texts"] = sorted(set(bad["texts"] + ["Unused target-derived payload."]), key=lambda text: text.encode())
    refused(lambda: codec.expand(new[0], question(codec, bad)))
    bad = copy.deepcopy(new[1])
    bad["label"] = 1
    refused(lambda: codec.expand(new[0], bad))
    refused(lambda: codec.expand('{"format":"first","format":"second"}', new[1]))
    refused(lambda: codec.expand("[" * 40 + "0" + "]" * 40, new[1]))
    refused(lambda: codec.expand(" " * (codec.MAX_BYTES + 1), new[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-dir", required=True)
    args = parser.parse_args()
    v1, codec = load(args.frozen_dir)
    value = fixture(v1)
    equality_gate(v1, codec, value)
    occurrence_gate(v1, codec, value)
    isolation_gate(v1, codec, value)
    require("torch" not in sys.modules and "transformers" not in sys.modules, "model import is forbidden")
    print(wire({"status": "pass", "groups": 3, "model_calls": 0, "tokenizer_calls": 0,
                "scope": "fixed-v1-normalized-lossless-codec", "native_authority_verified": False}))


if __name__ == "__main__":
    main()
