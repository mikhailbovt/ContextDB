# Continuous context comparisons

The shared generator lives in `contextdb-bench`; conformance imports the same
history. Emit a reproducible corpus with:

```console
cargo run --locked -p contextdb-bench --example continuous_history -- 1000
```

`events` contains original query-time inputs. `evaluation` is a separate target
partition and must never be sent to the reader or used as router features.
Every baseline uses the same generator version, distractor count, reader,
budgets and query cutoff. Required comparisons are rolling, good summary,
summary with archive/hybrid retrieval, raw hybrid retrieval and ContextDB R0.
Finite source contracts and actual reader measurements are separate artifacts.

`baseline.json` records the original engine's test run and environment. It is
not a new-runtime benchmark. The finite conformance oracle is independently
checked with:

```console
cargo test --locked -p contextdb-conformance --test continuous_context
```

Those abstract checks are distinct from native restart/race tests and model
quality measurements. See the [delivery ledger](../../docs/roadmap/continuous-context.md).

## Local reader replay

`run_reader.py` exercises the real native capture → R0 → owner admission → reader
→ output-capture path through `continuous_reader`. `corpus.py` contains a separate
RU/EN development corpus: old incidental details, corrections, prohibitions,
rejected alternatives, complementary originals, an attributed document, absent
information and a foreign-scope poison. Gold labels never enter preparation,
summary generation, embeddings or model requests.

Each question restores the same eight hot originals. Automatic retrieval has an
original-input time cutoff, and outgoing source spans are checked against that
partition and the current question. Previous replay answers remain auditable but
cannot help another question. IDs are deterministic hashes, without artificially
short numeric addresses. Native deep verification runs after every history.

The five treatments share the reader, 4,096-token input ceiling, 160-token output
ceiling and seeds. Summary generation uses the same reader, up to 1,024 output
tokens, and no questions. Both hybrid baselines use BM25 plus actual multilingual
embeddings and reciprocal-rank fusion. Selection precedes chronological rendering.
The rolling baseline fills the available recent window. R0 uses a 2,048-token
additional-memory allocation and its existing bounded lexical routes.

Pinned models (Apache-2.0) and backend:

| Component | Revision | SHA256 |
| --- | --- | --- |
| [Qwen3-8B-Q4_K_M.gguf](https://huggingface.co/Qwen/Qwen3-8B-GGUF/tree/7c41481f57cb95916b40956ab2f0b139b296d974) | `7c41481f57cb95916b40956ab2f0b139b296d974` | `d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785` |
| [Qwen3-Embedding-0.6B-Q8_0.gguf](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/tree/370f27d7550e0def9b39c1f16d3fbaa13aa67728) | `370f27d7550e0def9b39c1f16d3fbaa13aa67728` | `06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439` |
| [llama.cpp](https://github.com/ggml-org/llama.cpp/releases/tag/b10964) | `b10964`, commit `b29c606e28a01b1bc8c1351026a0fa6e616bf6c4` | Platform-specific binaries |

Keep weights and outputs outside the repository. Run the two local servers in
separate processes; create an empty slot directory before starting the reader:

```console
llama-server -m /models/Qwen3-8B-Q4_K_M.gguf -c 16384 -ngl 99 -np 1 --host 127.0.0.1 --port 18765 --no-webui --no-context-shift --cache-ram 0 --reasoning off --jinja --metrics --threads 8 --slot-save-path /outputs/slots
llama-server -m /models/Qwen3-Embedding-0.6B-Q8_0.gguf --embedding --pooling last -c 4096 -ub 2048 -b 2048 -ngl 99 -np 1 --host 127.0.0.1 --port 18766 --no-webui --cache-ram 0 --threads 8
cargo build --locked --release -p contextdb-bench --example continuous_reader
python benchmarks/continuous-context/run_reader.py --native target/release/examples/continuous_reader --output /outputs/reader-run --seeds 17 41
```

Use `.exe` executable suffixes on Windows and an explicit temporary directory on
the intended drive. Python 3.11+ and its standard library suffice. The adapter is
limited to the pinned Qwen ChatML text protocol, with reasoning disabled and no
tools. Unsupported protocol delimiters or missing endpoints fail explicitly.

The manifest hashes the native binary and Python drivers. External output holds
exact synthetic wires, responses, usage, stage timing and per-question evidence.
KV slots are erased between treatments; later questions may reuse only the
complete explicitly supplied prompt. `cache_n`/`prompt_n` are measured reuse/fresh
input; the post-generation `tokens_cached` counter is not used as a cache hit.

Whole-run wall time includes capture/index setup, summary generation, embeddings,
tokenization, decoding and failed attempts. Setup is charged at the actual eight
questions per history, never an invented large amortization count. Requested,
attempted and unstarted tasks are distinct. Answer accuracy and full original
exposure are reported separately: a correct guess is not evidence retrieval.
Dollar cost, physical I/O and energy remain unknown. Token tariffs are optional
explicit scenarios, not invoices or a claim that local computation is free.

These are finite one-step development probes, with four history/seed clusters.
Intervals are descriptive; they do not establish held-out generalization,
multi-step tool quality, multimodal capture, adaptive-cache savings or production
latency. The R0 content scorer and the optional residency controller are separate;
this replay fixes residency to isolate retrieval and assembly.

Accounting integrity is checked without a reader in CI:

```console
python -m unittest discover -s benchmarks/continuous-context -p test_reader.py -v
```

## Measured development result

[reader-results.json](reader-results.json) records the 20 September 2026 run:
Windows 11, release Rust 1.97.1, RTX 5080 Laptop GPU (16,303 MiB), two histories
and two seeds. All 160 questions completed without integration failure; native
source-partition checks and deep verification passed in all four native runs.

| Treatment | Correct / 32 | Whole run, s | s / attempt | s / correct | Task p95, s |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rolling | 10 | 70.55 | 2.20 | 7.05 | 2.89 |
| Summary | 23 | 36.26 | 1.13 | 1.58 | 0.40 |
| Summary + hybrid archive | 28 | 60.06 | 1.88 | 2.15 | 0.88 |
| Raw hybrid | 32 | 30.59 | 0.96 | 0.96 | 0.82 |
| ContextDB R0 | 24 | 30.10 | 0.94 | 1.25 | 1.54 |

R0 does not match the raw-hybrid baseline. It misses the old joke and prohibition
in all four repetitions. Only 20 of its 24 correct answers also receive every
required original; the complementary-source answer cannot count as a retrieval
success. The summary treatments receive the prohibition differently and answer
UNKNOWN, including when its original is present. This is a reader/context failure,
not evidence of permission to upload. No external tools run in this profile.

R0 reports 62,968 fresh and 5,476 reused input tokens; summary reports 36,137 fresh
and 22,605 reused, including all four summary-generation calls. Under the explicit
illustrative tariff in the JSON, summary's reader component costs 1,884.96
micro-units per correct answer versus R0's 2,720.33. This is a measured-token
counterexample to treating shorter residency as cheaper billing. It excludes
unpriced embedding/host work and is not total monetary cost. Whole-run wall time
above gives the separate local resource measurement.

R0 scorer calls total 11 microseconds at the local timer's resolution, while
tokenization RPCs take 8.45 seconds and measured prefill takes 14.36 seconds. The
request manifests attribute 72,320 source-echo bytes and 182,176 novel bytes.
Metadata-heavy rendering and bounded lexical selection remain improvement gates.
Rolling spends 56.33 seconds in repeated exact tokenization during eviction;
these measurements include the present drivers, not idealized algorithms.

These results do not establish a 30% total-cost saving, a production latency SLO
or an infinite-context guarantee. Improving retrieval and rendering must be
evaluated against this stronger raw-hybrid baseline before a learned scorer or
new default is accepted.
