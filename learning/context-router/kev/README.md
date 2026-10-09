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
vocabulary. Native StateKey/resolution/opaque facets refuse until a typed natural
adapter exists. Original source prose is preserved without UUID regex removal.
There is no native learned-scorer activation or private training intake here.

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
