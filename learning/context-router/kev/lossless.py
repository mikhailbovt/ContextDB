"""Lossless payload codec over the separately pinned conditional v1 normalizer.

This pure module does not admit a corpus, authorize sources, load a model or
change token limits. Its caller must load and pin the actual conditional module.
"""
from __future__ import annotations

import json

import conditional as v1

PROJECTION = "contextdb.kev-rendered-closure-lossless-projection.v2"
INSTRUCTION_PREFIX = "Does this proposed rendered closure add useful context beyond the selected base? "
OPTIONS = ["Useful", "Not useful"]
MAX_BYTES = 64 << 10
MAX_TEXTS = 4096
ASSEMBLY = {"blocks", "supports", "rendered_originals", "input_tokens", "count_kind",
            "wire_bytes", "added_original_bytes", "usage"}
BLOCK = {"kind", "representation", "exact_fragments", "epistemic", "interpretation",
         "source_class", "support", "valid_time", "use_action", "directive_reason", "facets", "supports"}


def _require(condition, code="invalid lossless projection"):
    if not condition:
        raise ValueError(code)


def _utf8(value):
    _require(type(value) is str)
    try:
        return value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid lossless UTF-8") from None


def _canonical(value):
    return v1.bounded_canonical(value, MAX_BYTES).decode("utf-8")


def _tree(value):
    """Bound borrowed wrappers before traversal/copies; payload strings stay exact."""
    remaining = [2 << 20, 65536]

    def visit(item, depth):
        remaining[1] -= 1
        _require(depth <= 32 and remaining[1] >= 0, "lossless structure ceiling")
        if type(item) is str:
            _require(len(item) <= remaining[0], "lossless byte ceiling")
            remaining[0] -= len(_utf8(item))
        elif type(item) is dict:
            _require(len(item) <= 128, "lossless object ceiling")
            for key, child in item.items():
                _require(type(key) is str)
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= MAX_TEXTS, "lossless inventory ceiling")
            for child in item:
                visit(child, depth + 1)
        else:
            _require(item is None or type(item) in {int, bool}, "lossless scalar refused")
            remaining[0] -= 24
        _require(remaining[0] >= 0, "lossless byte ceiling")

    visit(value, 0)
    _canonical(value)


def _parse(value):
    _require(type(value) is str and len(value) <= MAX_BYTES, "lossless byte ceiling")
    _require(len(_utf8(value)) <= MAX_BYTES, "lossless byte ceiling")
    # The structural pass is after parsing but the byte cap is before allocation.
    def pairs(items):
        result = {}
        for key, child in items:
            _require(key not in result, "duplicate lossless key")
            result[key] = child
        return result

    def reject(_):
        raise ValueError("lossless scalar refused")

    try:
        parsed = json.loads(value, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("invalid lossless JSON") from None
    _tree(parsed)
    return parsed


def _support(value, payload):
    v1.shape(value, {"excerpt", "primary", "source_class", "original_bytes"})
    _require(type(value["primary"]) is bool)
    v1.enum(value["source_class"], v1.SOURCES)
    if value["original_bytes"] is not None:
        v1.integer(value["original_bytes"])
    return dict(value, excerpt=None if value["excerpt"] is None else payload(value["excerpt"]))


def _message(value, payload, protocol=False):
    keys = {"zone", "role", "text"} | ({"tool_calls", "tool_result"} if protocol else set())
    v1.shape(value, keys)
    v1.enum(value["zone"], v1.ZONES)
    v1.enum(value["role"], v1.ROLES)
    return dict(value, text=payload(value["text"]))


def _block(value, payload, trial):
    flags = {"seed", "added_closure"} if trial else set()
    v1.shape(value, BLOCK | flags, {"conflict", "unknown"})
    v1.enum(value["kind"], v1.KINDS)
    v1.enum(value["source_class"], v1.SOURCES)
    v1.enum(value["interpretation"], {"factual_data", "historical_data", "constraint_data", "style_signal",
                                      "hypothesis_only", "unknown_marker", "conflict_alternatives"})
    for key, allowed in (("use_action", {"mention_naturally", "use_silently", "constraint_only", "style_only"}),
                         ("directive_reason", {"policy_allows_mention", "mention_denied", "explicit_request_required",
                                               "constraint_semantics", "style_semantics"})):
        if value[key] is not None:
            v1.enum(value[key], allowed)
    for key in flags:
        _require(type(value[key]) is bool)
    rep = value["representation"]
    v1.shape(rep, {"level", "summary", "fields", "omitted_facets"})
    v1.enum(rep["level"], {"l0_orientation", "l1_summary", "l2_structured", "l3_evidence", "l4_raw"})
    _require(rep["omitted_facets"] == [] and value["facets"] == [])
    if value["kind"] == "raw_observation":
        _require(rep["summary"] is None and rep["fields"] is None)
        representation = dict(rep)
    else:
        _require(type(rep["fields"]) is dict and set(rep["fields"]) <= v1.FIELDS)
        representation = dict(rep, summary=payload(rep["summary"]),
                              fields={v1.natural(key): payload(text) for key, text in rep["fields"].items()})
    fragments = []
    for item in v1.array(value["exact_fragments"], 64):
        v1.shape(item, {"label", "value"})
        v1.natural(item["label"])
        fragments.append(dict(item, value=payload(item["value"])))
    epistemic = value["epistemic"]
    v1.shape(epistemic, {"basis", "acceptance", "conflict", "lifecycle"})
    v1.enum(epistemic["basis"], {"observation", "actor_assertion", "model_inference", "deterministic_derivation",
                                "human_adjudication", "hypothesis"})
    v1.enum(epistemic["acceptance"], {"proposed", "validated", "accepted", "consolidated", "rejected"})
    v1.enum(epistemic["lifecycle"], {"active", "historical", "superseded", "retracted", "suppressed", "deleted"})
    v1.shape(epistemic["conflict"], {"state"})
    v1.enum(epistemic["conflict"]["state"], {"none", "disputed", "in_conflict", "resolved"})
    support = value["support"]
    v1.shape(support, {"state"}, {"reason"})
    v1.enum(support["state"], {"supported", "unsupported"})
    _require((support["state"] == "unsupported") == ("reason" in support))
    support = dict(support)
    if "reason" in support:
        support["reason"] = payload(support["reason"])
    validity = value["valid_time"]
    if validity is not None:
        v1.shape(validity, {"start", "end"})
        v1.integer(validity["start"], minimum=-(1 << 63))
        if validity["end"] is not None:
            v1.integer(validity["end"], minimum=-(1 << 63))
            _require(validity["end"] > validity["start"])
    result = dict(value, representation=representation, exact_fragments=fragments, support=support,
                  supports=[_support(item, payload) for item in v1.array(value["supports"], 128)])
    if "conflict" in value:
        item = value["conflict"]
        v1.shape(item, {"blocking", "alternatives", "resolved", "rationale"})
        _require(type(item["blocking"]) is bool and type(item["resolved"]) is bool)
        v1.integer(item["alternatives"], 64)
        result["conflict"] = dict(item, rationale=None if item["rationale"] is None else payload(item["rationale"]))
    if "unknown" in value:
        item = value["unknown"]
        v1.shape(item, {"question", "reason", "blocking"})
        _require(type(item["blocking"]) is bool)
        result["unknown"] = dict(item, question=payload(item["question"]), reason=payload(item["reason"]))
    return result


def _assembly(value, payload, trial=False):
    v1.shape(value, ASSEMBLY)
    for key in ("input_tokens", "wire_bytes", "added_original_bytes"):
        v1.integer(value[key])
    v1.enum(value["count_kind"], {"exact", "conservative_upper_bound"})
    v1.numeric(value["usage"], v1.USAGE)
    return dict(value,
                blocks=[_block(item, payload, trial) for item in v1.array(value["blocks"], 64)],
                supports=[_support(item, payload) for item in v1.array(value["supports"], 128)],
                rendered_originals=[_message(item, payload) for item in v1.array(value["rendered_originals"], 128)])


def _state(value, payload):
    v1.shape(value, {"profile", "base", "selected", "memory_limits", "outgoing_limits"})
    _require(value["profile"] == v1.PROJECTION)
    v1.numeric(value["memory_limits"], v1.MEMORY - {"max_selection_evaluations"})
    v1.numeric(value["outgoing_limits"], v1.OUTGOING)
    messages, next_call = [], 0
    for item in v1.array(value["base"], 512):
        message = _message(item, payload, protocol=True)
        calls = v1.array(message["tool_calls"], 64)
        _require(all(type(slot) is int for slot in calls) and calls == list(range(next_call, next_call + len(calls))))
        next_call += len(calls)
        result = message["tool_result"]
        _require(result is None or type(result) is int and 0 <= result < next_call)
        messages.append(message)
    return dict(value, base=messages, selected=_assembly(value["selected"], payload))


def _branch(value, payload):
    v1.shape(value, {"trial", "exact_marginal_input_tokens", "outgoing_fits"})
    _require(type(value["outgoing_fits"]) is bool)
    if value["exact_marginal_input_tokens"] is not None:
        v1.integer(value["exact_marginal_input_tokens"], minimum=-(1 << 63))
    return dict(value, trial=_assembly(value["trial"], payload, trial=True))


def _question(question):
    v1.shape(question, {"instr", "options", "label"})
    _require(question["options"] == OPTIONS and type(question["label"]) is int and question["label"] == 0,
             "lossless question has no supervision")
    _require(type(question["instr"]) is str and question["instr"].startswith(INSTRUCTION_PREFIX),
             "lossless instruction mismatch")
    return _parse(question["instr"][len(INSTRUCTION_PREFIX):])


def _table(record, walker, exclude=()):
    strings = set()

    def collect(value):
        v1.text(value)
        strings.add(value)
        _require(len(strings) <= MAX_TEXTS, "lossless text inventory ceiling")
        return value

    walker(record, collect)
    return sorted(strings - set(exclude), key=_utf8)


def _normalized(state_text, question):
    state, branch = _parse(state_text), _question(question)
    state_texts = _table(state, _state)
    trial_texts = _table(branch, _branch, state_texts)
    state_slots = {text: index for index, text in enumerate(state_texts)}
    trial_slots = {text: index for index, text in enumerate(trial_texts)}

    def state_ref(value):
        return {"state": state_slots[value]}

    def trial_ref(value):
        return state_ref(value) if value in state_slots else {"trial": trial_slots[value]}

    encoded_record = _state(state, state_ref)
    # The declared v2 codec and pinned v1 normalizer determine this constant.
    # Reconstruct it on expansion rather than repeating both version markers.
    encoded_record.pop("profile")
    encoded_state = {"format": PROJECTION, "texts": state_texts, "record": encoded_record}
    encoded_trial = {"format": PROJECTION, "texts": trial_texts, "record": _branch(branch, trial_ref)}
    _tree(encoded_state)
    _tree(encoded_trial)
    return _canonical(encoded_state), {"instr": INSTRUCTION_PREFIX + _canonical(encoded_trial),
                                       "options": list(OPTIONS), "label": 0}


def project(input_value):
    """Normalize through frozen v1, then intern only declared payload leaves."""
    return _normalized(*v1.project(input_value))


def expand(state_text, question):
    """Strict cold expansion to the exact old normalized pair; no authority claim."""
    state, trial = _parse(state_text), _question(question)
    for wrapper in (state, trial):
        v1.shape(wrapper, {"format", "texts", "record"})
        _require(wrapper["format"] == PROJECTION, "lossless format mismatch")
        texts = v1.array(wrapper["texts"], MAX_TEXTS)
        for text in texts:
            v1.text(text)
        _require(texts == sorted(set(texts), key=_utf8), "noncanonical lossless text table")
    _require(not set(state["texts"]) & set(trial["texts"]), "trial table repeats state payload")
    state_used, trial_used = set(), set()

    def decode(value, allow_trial=False):
        _require(type(value) is dict and len(value) == 1, "invalid lossless payload reference")
        key = next(iter(value))
        _require(key == "state" or allow_trial and key == "trial", "invalid lossless reference scope")
        table = state if key == "state" else trial
        index = value[key]
        _require(type(index) is int and 0 <= index < len(table["texts"]), "invalid lossless reference index")
        (state_used if key == "state" else trial_used).add(index)
        return table["texts"][index]

    v1.shape(state["record"], {"base", "selected", "memory_limits", "outgoing_limits"})
    restored_state = _state(dict(state["record"], profile=v1.PROJECTION), decode)
    # State-local table admission cannot be rescued by a later trial reference.
    _require(state_used == set(range(len(state["texts"]))), "unused lossless state payload")
    restored_trial = _branch(trial["record"], lambda value: decode(value, allow_trial=True))
    _require(trial_used == set(range(len(trial["texts"]))), "unused lossless trial payload")
    _tree(restored_state)
    _tree(restored_trial)
    return _canonical(restored_state), {"instr": INSTRUCTION_PREFIX + _canonical(restored_trial),
                                        "options": list(OPTIONS), "label": 0}
