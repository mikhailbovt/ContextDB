"""Pinned llama.cpp text benchmark client; no cloud endpoint or silent fallback."""

import hashlib
import json
import math
import time
import urllib.parse
import urllib.request


def micros(start):
    return (time.perf_counter_ns() - start) // 1000


class Client:
    def __init__(self, endpoint):
        url = urllib.parse.urlparse(endpoint)
        if url.scheme != "http" or url.hostname not in (
            "127.0.0.1",
            "localhost",
            "::1",
        ):
            raise ValueError(
                "this synthetic benchmark requires an explicit loopback endpoint"
            )
        self.endpoint = endpoint.rstrip("/")
        self.count_cache = {}
        self.calls = []
        self.tokenization_micros = 0
        self.tokenization_calls = 0

    def post(self, path, value=None, wire=None):
        if wire is None:
            wire = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        req = urllib.request.Request(
            self.endpoint + path,
            data=wire,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.load(response)

    def count(self, text, special=False):
        key = (hashlib.sha256(text.encode()).digest(), special)
        if key not in self.count_cache:
            start = time.perf_counter_ns()
            self.tokenization_calls += 1
            try:
                response = self.post(
                    "/tokenize",
                    {"content": text, "add_special": special, "parse_special": special},
                )
            finally:
                self.tokenization_micros += micros(start)
            count = len(response["tokens"])
            if len(self.count_cache) >= 4096:
                self.count_cache.clear()
            self.count_cache[key] = count
        return self.count_cache[key]

    def clear_slot(self):
        # Erase KV reuse between treatments, without pretending prefix similarity
        # measures actual hits. A missing endpoint fails the benchmark explicitly.
        self.post("/slots/0?action=erase", {})
        self.count_cache.clear()

    @staticmethod
    def prompt(messages):
        for message in messages:
            if "<|im_" in message["content"] or "<|endoftext|>" in message["content"]:
                raise ValueError("unsupported protocol delimiter in benchmark content")
        return (
            "".join(
                f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n" for m in messages
            )
            + "<|im_start|>assistant\n<think>\n\n</think>\n\n"
        )

    def complete_wire(self, wire, expected_input, stage="reader"):
        start = time.perf_counter_ns()
        record = {
            "stage": stage,
            "wire_bytes": len(wire),
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "usage": None,
            "elapsed_micros": None,
            "completed": False,
            "wire": wire.decode("utf-8"),
        }
        self.calls.append(record)  # failed/ambiguous attempts remain in run cost
        try:
            result = self.post("/completion", wire=wire)
            text = result["content"]
            if not isinstance(text, str):
                raise TypeError("reader returned no visible text")
            # Preserve visible output before checking auxiliary usage counters.
            # A measurement error must not turn observed bytes into no output.
            record["text"] = text
            timings = result.get("timings", {})
            total, read, fresh = (
                result.get("tokens_evaluated"),
                timings.get("cache_n"),
                timings.get("prompt_n"),
            )
            valid_usage = not (
                total != expected_input
                or not all(type(v) is int and v >= 0 for v in (total, read, fresh))
                or fresh + read != total
                or type(result.get("tokens_predicted")) is not int
                or result["tokens_predicted"] < 0
            )
            usage = (
                {
                    "input_tokens": total,
                    "uncached_input_tokens": fresh,
                    "cache_write_tokens": 0,
                    "cache_read_tokens": read,
                    "output_tokens": result.get("tokens_predicted"),
                    "reasoning_tokens": 0,
                    "prefill_micros": round(timings["prompt_ms"] * 1000)
                    if type(timings.get("prompt_ms")) in (int, float)
                    and math.isfinite(timings["prompt_ms"])
                    and timings["prompt_ms"] >= 0
                    else None,
                }
                if valid_usage
                else None
            )
            protocol_valid = "<think>" not in text and "</think>" not in text
            if not valid_usage:
                record["measurement_error"] = (
                    "tokenizer/cache counters differ from captured input"
                )
            if not protocol_valid:
                record["protocol_error"] = "disabled-reasoning profile violation"
            completed = (
                protocol_valid
                and result.get("stop_type") == "eos"
                and not result.get("truncated", True)
            )
            record.update(usage=usage, completed=completed, text=text, timings=timings)
            return {"text": text, "usage": usage, "completed": completed}
        finally:
            record["elapsed_micros"] = micros(start)

    def complete(self, messages, seed, output_tokens=160, stage="reader"):
        prompt = self.prompt(messages)
        value = {
            "prompt": prompt,
            "n_predict": output_tokens,
            "temperature": 0.7,
            "top_k": 20,
            "top_p": 0.8,
            "min_p": 0,
            "presence_penalty": 1.5,
            "seed": seed,
            "cache_prompt": True,
            "id_slot": 0,
            "stream": False,
        }
        wire = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        return self.complete_wire(wire, self.count(prompt, True), stage)

    def embeddings(self, texts):
        start = time.perf_counter_ns()
        record = {
            "stage": "embedding",
            "inputs": len(texts),
            "completed": False,
            "usage": None,
        }
        self.calls.append(record)
        try:
            result = self.post(
                "/v1/embeddings", {"input": texts, "encoding_format": "float"}
            )
            data = sorted(result["data"], key=lambda item: item["index"])
            if [item["index"] for item in data] != list(range(len(texts))):
                raise ValueError("embedding output indices differ")
            record.update(completed=True, usage=result.get("usage"))
            return [item["embedding"] for item in data]
        finally:
            record["elapsed_micros"] = micros(start)
