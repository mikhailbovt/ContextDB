"""Owned deterministic protocol fixture; never a model quality evaluation."""
import argparse
import json
import os
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--log")
parser.add_argument("--mode", default="reply")
parser.add_argument("--alive-check", type=int)
args = parser.parse_args()

if args.alive_check is not None:
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x1000, False, args.alive_check)
        code = ctypes.c_ulong()
        alive = bool(handle and kernel.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value == 259)
        if handle:
            kernel.CloseHandle(handle)
    else:
        try:
            os.kill(args.alive_check, 0)
            alive = True
        except ProcessLookupError:
            alive = False
    print(json.dumps({"alive": alive}))
    sys.exit(0)


def record(request):
    with open(args.log, "a", encoding="utf-8") as log:
        log.write(json.dumps({"pid": os.getpid(), "request": request}) + "\n")
        log.flush()
        os.fsync(log.fileno())


def count(text):
    total = 0
    word = False
    for char in text:
        if char.isalnum() or char == "_":
            total += not word
            word = True
        else:
            word = False
            total += not char.isspace()
    return total


try:
    record({"op": "process_environment", "contains_token": "CONTEXTDB_TOKEN_KEY_HEX" in os.environ,
            "contains_master": "CONTEXTDB_NATIVE_MASTER_KEY_HEX" in os.environ})
    for line in sys.stdin:
        request = json.loads(line)
        record(request)
        op = request["op"]
        if op == "hello":
            response = {"profile": request["profile"], "encoder": request["encoder"], "tokenizer": request["tokenizer"]}
        elif op == "tokenize":
            response = {"count": count(request["text"])}
        elif op == "complete":
            if args.mode == "lost":
                os._exit(0)
            if args.mode == "deadline":
                time.sleep(10)
            if args.mode == "large":
                response = {"completed": True, "text": "bridge-private-sentinel-7319" * 100000, "usage": None}
            elif args.mode == "invalid_partial":
                response = {"completed": True, "text": "bridge-private-sentinel-7319 visible observed bytes",
                            "usage": None, "partial": {"bytes": [65], "media_type": "unsupported"}}
            else:
                response = {"completed": True, "text": "Visible deterministic reply.", "usage": None}
        else:
            raise ValueError("unknown operation")
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
except Exception:
    sys.stderr.write("fixture peer protocol failure\n")
    sys.exit(2)
