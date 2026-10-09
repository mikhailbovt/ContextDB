# Kev synthetic development trainer

This optional tool uses the pinned Kev-0.8B adapter and pointer head on
Qwen3.5-0.8B-Base. Utility is an independent
`sigmoid(useful_logit - not_useful_logit)` with masked multi-label BCE.
It accepts two exact built-in public synthetic corpora. The initial-context
profile has 32 examples: eight train, eight development, eight test and eight
quarantined. The rendered-closure profile has 48 cases and 268 actual
compiler callbacks. Only train and development reach the formatter, tokenizer
or model. Arbitrary or private corpus intake and training-purpose admission are
unsupported.

The semantic formatter includes natural query/current conversation and attributed
raw excerpts, roles and relative age. It removes fixture summaries, IDs, scopes,
UUIDs, hashes, absolute counters, R0 behavior and evaluator data. Opaque memory
slots are permuted without labels; every optional pair is proposed from inputs
before target joins. Unknown targets stay masked; all-zero, multiple-positive and
positive complementary unions retain their supervision. This small corpus has
no supervised negative bundles.

This is the **initial-context** development profile. Hard/complement dependency
links, non-Situation mandatory material and tool protocols refuse until their
branch-visible semantic closure is implemented. It does not provide the live
compiler selected-base/trial scoring interface, calibrated marginal utility,
high-recall retrieval, serving latency, held-out quality or reader benefit.

The separate **rendered-closure** profile consumes real compiler callbacks from
the fixed public conditional corpus. Its common state contains current
control/tool/working/hot messages and the actual selected base. Each question
contains its own chosen support, hard/complement closure, rendered source union
and complete request cost. Inputs are collected before source-coverage labels;
R0 behavior and final selection never become utility gold. Coverage is a
synthetic surrogate, not measured reader benefit. Partial complementary gains
remain masked when their independent usefulness is unknown; resident and
irrelevant negatives require explicit evaluator evidence.

Both training and future inference use `conditional.project`. It excludes
alternative ordinals, search/time counters and host associations while retaining
permission directives and semantic costs. It canonicalizes unordered block and
support inventories, including equal supports, but preserves conversation, tool
and rendered-source chronology. Nonraw fields accept only declared natural
`question`, `reason` and `missing_facet` keys; this fixed fixture has no facet
vocabulary. Opaque native StateKey/resolution/facets refuse through this projection;
supported native values require the owner's typed natural adapter. Original source
prose is preserved without UUID regex removal. The trainer itself neither activates
a native scorer nor admits private training data.

## Local setup

Use Python 3.12, Git and complete local snapshots. The shipped
`model-lock.example.json` lists public repositories, immutable revisions, consumed
file sizes/SHA256 hashes, architecture and tested package versions. Copy it outside
the repository and fill only `paths.source`, `paths.adapter` and `paths.base` with
absolute resolved local directories. Other changes are refused. No credentials,
weights, machine paths or run artifacts belong in the published folder.

- Source: [jaredpalmer/kev](https://github.com/jaredpalmer/kev), revision
  `5e42a7a03f28134853dd3ff77461457e921e5ec1`.
- Adapter/head: [jaredpalmer/kev-0.8b](https://huggingface.co/jaredpalmer/kev-0.8b),
  revision `9a45d25eb2ab761841196625383fa1dff0e56c1e`.
- Backbone/tokenizer: [Qwen/Qwen3.5-0.8B-Base](https://huggingface.co/Qwen/Qwen3.5-0.8B-Base),
  revision `dc7cdfe2ee4154fa7e30f5b51ca41bfa40174e68`.

Install the exact package versions from the lock into an isolated environment;
the tested Torch build is `2.8.0+cu128`. Install the pinned Kev source locally
without allowing dependency resolution to replace those versions. Preflight
checks the source commit, dirty tracked/untracked files (only generated `build/`
is allowed), consumed files and runtime versions. Model loading is offline and
uses the inspected exact adapter key loader plus strict pointer head loading;
it avoids the unrelated Unix-only `fcntl` import in upstream warm-start code.

Generate and cold-verify the built-in replay corpus using the commands in the
[corpus guide](../README.md). Its admitted manifest is
`a6d856160f964b8905d943acc75a38aa6a2d1c9b4ba8adfc35428a3b21c026ab`;
all six artifacts must match the tool's fixed SHA256 allowlist. Preflight hashes
the containing files but never renders test or quarantined examples.

## Commands

Create an owned output directory first. Supply absolute paths in place of the
placeholders below; the commands work with the environment's Python executable.

```text
python learning/context-router/kev/check.py --corpus /absolute/replay-corpus
python learning/context-router/kev/trainer.py preflight --corpus /absolute/replay-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs
python learning/context-router/kev/trainer.py train --corpus /absolute/replay-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs --run-name development-v1 --epochs 1 --lr 0.00001
python learning/context-router/kev/trainer.py verify-bundle --corpus /absolute/replay-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs --run-name development-v1
```

For the distinct conditional corpus, explicitly select the new profile:

```text
python learning/context-router/kev/check.py --profile rendered-closure --corpus /absolute/conditional-corpus
python learning/context-router/kev/trainer.py preflight --profile rendered-closure --corpus /absolute/conditional-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs
python learning/context-router/kev/trainer.py train --profile rendered-closure --corpus /absolute/conditional-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs --run-name conditional-v1 --epochs 1 --lr 0.00001
python learning/context-router/kev/trainer.py verify-bundle --profile rendered-closure --corpus /absolute/conditional-corpus --model-lock /absolute/model-lock.json --output-root /absolute/runs --run-name conditional-v1
```

The model lock stays unchanged: it pins the source/runtime and upstream warm-start
weights, not compatibility between feature profiles. Conditional training starts
from those upstream weights; it does not load the initial-context trained bundle.
Conditional bundles have a distinct format, formatter/source commitments and
corpus pins. Old initial-context bundles are rejected by the conditional path.
The public artifact allowlist is installed only after actual generation and cold
verification; a self-declared synthetic/private directory is not accepted.
The pinned conditional manifest is
`ef04265b868160f81902b5144a0115934fe0af10bcd6a59843eae20f3a286eac`:
48 cases and 268 callbacks, with 12 cases/67 callbacks per fold and one
independent connected source group per fold. Its admitted population is 24
supervised train and 24 development base groups; 134 held-out
callbacks and two train/development all-unknown groups never reach the model.

`check.py` uses only the standard library: three grouped gates cover input/label
isolation, independent/bundle masks and strict lock/intake/persistence bounds.
`preflight` loads no model. Training and fresh-process verification require BF16
CUDA and at least 4 GiB free VRAM before model construction; other applications
remain running. Paths work on Windows and Linux; Linux GPU execution has not been
established by a Windows result.

Each known question runs alone. Its BCE/known-count gradient accumulates before
one AdamW step per example; unknown questions contribute no loss. In the
initial-context profile, one epoch takes eight steps, with finite checks and
actual nonzero changes in both LoRA and head.
Development uses `no_grad`; the threshold is fixed at 0.5 and is not calibrated.
Limits are four optional memories, six pairs, ten questions, 12 KiB state/branch
text, 384 state tokens, 1024 tokens per row and 4096 packed tokens. Oversized data,
OOM and nonfinite results fail without truncation or automatic retry. The
cooperative run ceiling is 30 minutes; at most two epochs are supported.

Conditional limits are 512 callbacks, 64 cases and 64 MiB across the five corpus
files, at most 2 MiB per raw callback, 16 observed questions per exact selected
base, and 64 supervised train/development groups each. All callbacks from one
history/source/session stay in one lineage fold. Test/quarantined rows are
excluded before Python projection, tokenization or model use. Entire groups and
all train/development token records must fit before the first optimizer step:
2048 state tokens, 4096 per state-plus-question row and 65536 packed admission
tokens. GPU execution still holds one question graph at a time. Exactly one
epoch, at most 64 optimizer steps, is supported; all-unknown groups are explicitly
reported and contribute no loss. Overflow rejects the whole run, never a prefix.

A run writes a unique partial sibling and publishes a completed directory by an
atomic no-replace rename. Failures preserve the partial directory; existing runs
are never overwritten or resumed. Adapter/head safetensors, optimizer evidence
and metadata have fixed names and individual/total byte caps checked before
hashing or tensor loading. The optimizer is not loaded by verification.

Completion requires exact tensor coverage and a cold model reproducing one
development row's logits. `verify-bundle` repeats that check in a fresh process
under the same pinned runtime. The prior development bundle remains readable
when its model files, revisions, package profile and synthetic data match these
pins. Verification establishes artifact/logit reproducibility, never source-use
permission, model usefulness or benchmark completion.

## Local inference worker

`worker.py` keeps one pinned conditional model loaded for a trusted local host.
It reuses the same `conditional.project`, strict tokenizer admission and bundle
loader, with one question per forward, `eval`, `no_grad` and temperature 1. It
returns the finite useful-minus-not-useful logit; the host applies independent
sigmoid and its explicitly bound STOP/utility conversion. It performs no training,
corpus export, network fallback or context logging/caching.

The current conditional bundle is **development only**. Its 24 real updates and
cold reload pass establish plumbing; at the fixed 0.5 threshold it marked all 59
known development questions useful, including 28 negatives, and failed every
all-zero base. Default R0 remains unchanged. Useful scoring, calibration,
held-out reader quality and serving latency are not established.

The host starts this process with absolute paths and exact pins:

```text
python -I worker.py --corpus ABS --model-lock ABS --output-root ABS \
  --run-name NAME --bundle-sha256 HEX --worker-sha256 HEX \
  --config-sha256 HEX --startup-timeout-micros 300000000
```

Warm admission checks the completed rendered-closure bundle, exact trained source
hashes and model/runtime pins before GPU construction, then reproduces the saved
public development row before emitting READY. Old initial-context bundles refuse.
The corpus path supplies only that fixed public sanity input; it grants no native
inference or private training rights. Current native ModelProcessing scopes and
the whole processed source frontier must be admitted by the host before input is
sent. Unsupported native metadata refuses through the unchanged projection.

Binary framing is big-endian u32 body length, u16 metadata length, strict JSON
metadata followed by exact semantic JSON bytes. Metadata/replies are bounded to
16 KiB; input to 2 MiB. READY binds bundle, model profile, tensor, worker and four
trained source hashes. Each score uses a sequential ID, immutable configuration
hash, exact input SHA256 and remaining timeout. Only one request is in flight.
The same parent deadline includes IPC, projection, tokenization and inference;
late, malformed, nonfinite, oversized or failed requests invalidate the process.
No timeout reset, hidden retry or fallback occurs in the worker. Library stdout
and stderr are suppressed; protocol replies and fixed error codes use reserved
pipe handles. CUDA cancellation remains cooperative, with the host rejecting late
results and terminating the child.

Pure checks use no tokenizer or model:

```text
python -I worker_check.py --corpus ABS --old-bundle ABS
```

Three grouped gates cover framing/correlation, exact shared projection and strict
single-row admission, plus deadline/nonfinite/log isolation and old-profile
refusal. Actual warm and persistent inference checks require the pinned CUDA
environment and are separate from these pure gates.

## Native owned host

`owned-conversation` accepts optional `development_kev` only in trusted operator
configuration, with `router_trace_profile: required` or `required_replay_v2` and
`development_only`/`model_processing` both true. The native owner requires current
`ModelProcessing` capability and admits the whole processed source frontier for
the actual database, scopes and purpose, even when the main reader's
`external_processing` is false.

Absolute paths, executable/worker/trained-source/model/weight pins and limits bind
the retained run configuration. Resume verifies that binding before worker warm
or reader launch. Startup is at most 300,000,000 microseconds; aggregate and
per-call scoring allowances are at most 10,000,000 microseconds. The experimental
utility uses independent sigmoid, with the fixed 0.5 STOP threshold.
The trained projection strictly admits 2048 state tokens and 4096 per row; longer
native owned-conversation gates are not established. Oversize refuses instead of
silently switching to R0.
An end-to-end learned eviction and cold-resume run remains unverified.
Complete reader-request overflow can trigger bounded eviction of closed hot
exchanges using the remaining parent allowance. Worker, closure and work/deadline
failures remain refusals.

The typed adapter supports literal Known state, Conflict/Unknown diagnostics and
exact attributed sources through the same projection. Opaque generic metadata,
Node/CodeLocation and arbitrary Structured values refuse before forward. Current
admission is a check at the processing boundary, not atomic revocation during GPU
execution. Configuration and hashes grant no private training or export rights.
