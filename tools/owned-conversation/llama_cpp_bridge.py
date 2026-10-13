"""Bounded private JSONL connector for a host-owned local llama.cpp reader.

Run by the ContextDB owned conversation host, not as the user conversation UI.
The configured server/model/flags are a trusted deployment contract. No prompt
or response log, persistent conversation, remote fallback or HTTP proxy exists.
"""

import argparse
import http.client
import json
import math
import sys
import time
import urllib.parse

MAX_FRAME = 16 * 1024 * 1024
MAX_WIRE = 2 * 1024 * 1024
MAX_HTTP = 32 * 1024
MAX_VISIBLE = 32 * 1024
ENCODER = "llama.cpp.qwen3-chatml-json.v1"


class Refused(Exception):
    pass


class Interrupted(Exception):
    def __init__(self, body):
        self.body = body[:MAX_VISIBLE]


def checked_object(value, keys, required=()):
    if not isinstance(value, dict) or set(value) - set(keys) or set(required) - set(value):
        raise Refused()


def integer(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


class Client:
    def __init__(self, endpoint, timeout_millis):
        parsed = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in ("127.0.0.1", "::1")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or not parsed.port
            or not 50 <= timeout_millis <= 120000
        ):
            raise Refused()
        self.host, self.port = parsed.hostname, parsed.port
        self.timeout = timeout_millis / 1000
        self.profile = None

    def request(self, path, wire=None, limit=MAX_HTTP):
        deadline = time.monotonic() + self.timeout
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        body = bytearray()
        try:
            connection.request(
                "POST" if wire is not None else "GET",
                path,
                body=wire,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise Refused()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(16384, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > limit:
                    raise Interrupted(body)
            try:
                return json.loads(body)
            except (ValueError, UnicodeError):
                raise Interrupted(body) from None
        except (OSError, TimeoutError, http.client.HTTPException):
            if body:
                raise Interrupted(body) from None
            raise Refused() from None
        finally:
            connection.close()

    def hello(self, request):
        checked_object(request, ("op", "profile", "encoder", "tokenizer"), ("profile",))
        profile = request["profile"]
        if (
            not isinstance(profile, dict)
            or request.get("encoder") != ENCODER
            or request.get("tokenizer") != profile.get("tokenizer_id")
            or profile.get("family") != "Qwen3-8B-GGUF"
            or profile.get("external_processing") is not False
            or profile.get("supports_tool_results") is not False
        ):
            raise Refused()
        # Existing server availability and model identity; launch/version/flags
        # are pinned and verified by the deployment's actual acceptance receipt.
        properties = self.request("/props")
        model_path = properties.get("model_path")
        if model_path is not None:
            basename = model_path.replace("\\", "/").rsplit("/", 1)[-1]
            if basename != profile.get("id") + ".gguf":
                raise Refused()
        self.profile = profile
        return {"profile": profile, "encoder": ENCODER, "tokenizer": profile["tokenizer_id"]}

    def tokenize(self, request):
        checked_object(request, ("op", "text", "special"), ("text", "special"))
        if not isinstance(request["text"], str) or type(request["special"]) is not bool:
            raise Refused()
        if len(request["text"].encode("utf-8")) > MAX_WIRE:
            raise Refused()
        wire = json.dumps(
            {"content": request["text"], "add_special": request["special"], "parse_special": request["special"]},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        result = self.request("/tokenize", wire, limit=256 * 1024)
        tokens = result.get("tokens")
        if not isinstance(tokens, list) or not all(integer(value) for value in tokens):
            raise Refused()
        return {"count": len(tokens)}

    def complete(self, request):
        checked_object(request, ("op", "call", "outgoing"), ("call", "outgoing"))
        outgoing = request["outgoing"]
        checked_object(outgoing, ("protocol", "tokenizer", "count_kind", "input_tokens", "wire"),
                       ("protocol", "tokenizer", "count_kind", "input_tokens", "wire"))
        raw = outgoing["wire"]
        if (
            outgoing["protocol"] != ENCODER
            or outgoing["tokenizer"] != self.profile["tokenizer_id"]
            or outgoing["count_kind"] != "exact"
            or not integer(outgoing["input_tokens"])
            or not isinstance(raw, list) or len(raw) > MAX_WIRE
            or not all(type(value) is int and 0 <= value <= 255 for value in raw)
        ):
            raise Refused()
        wire = bytes(raw)
        options = json.loads(wire)
        if (
            options.get("stream") is not False or options.get("cache_prompt") is not True
            or options.get("id_slot") != 0
            or options.get("n_predict") != self.profile["reserved_output_tokens"]
            or not isinstance(options.get("prompt"), str)
        ):
            raise Refused()
        # The captured wire is passed directly, without JSON reserialization.
        try:
            result = self.request("/completion", wire)
        except Interrupted as partial:
            return {"partial": {"bytes": list(partial.body), "media_type": "application/json"}}
        text = result.get("content")
        if not isinstance(text, str):
            raise Refused()
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_VISIBLE:
            return {"partial": {"bytes": list(encoded[:MAX_VISIBLE]), "media_type": "text/plain; charset=utf-8"}}
        timings = result.get("timings", {})
        if not isinstance(timings, dict):
            timings = {}
        total, read, fresh, output = result.get("tokens_evaluated"), timings.get("cache_n"), timings.get("prompt_n"), result.get("tokens_predicted")
        valid_usage = (
            all(integer(value) for value in (total, read, fresh, output))
            and total == outgoing["input_tokens"] and fresh + read == total
        )
        prefill = timings.get("prompt_ms")
        prefill = round(prefill * 1000) if type(prefill) in (int, float) and math.isfinite(prefill) and prefill >= 0 else None
        usage = {
            "input_tokens": total, "uncached_input_tokens": fresh, "cache_write_tokens": 0,
            "cache_read_tokens": read, "output_tokens": output, "reasoning_tokens": 0,
            "prefill_micros": prefill,
        } if valid_usage else None
        completed = (
            valid_usage and result.get("stop_type") == "eos" and result.get("truncated") is False
            and "<think>" not in text and "</think>" not in text
        )
        return {"completed": completed, "text": text, "usage": usage}

    def dispatch(self, request):
        if not isinstance(request, dict):
            raise Refused()
        operation = request.get("op")
        if operation == "hello" and self.profile is None:
            return self.hello(request)
        if self.profile is None:
            raise Refused()
        if operation == "tokenize":
            return self.tokenize(request)
        if operation == "complete":
            return self.complete(request)
        raise Refused()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--timeout-millis", type=int, default=120000)
    options = parser.parse_args()
    client = Client(options.endpoint, options.timeout_millis)
    while True:
        line = sys.stdin.buffer.readline(MAX_FRAME + 1)
        if not line:
            return
        if len(line) > MAX_FRAME or not line.endswith(b"\n"):
            return
        try:
            request = json.loads(line)
            response = client.dispatch(request)
        except Exception:
            # No endpoint, exception, prompt or provider body is reflected.
            response = {"error": "local_reader_refused"}
        encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) + 1 > MAX_FRAME:
            return
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
