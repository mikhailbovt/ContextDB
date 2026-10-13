# Context router corpus

The learned router will use independent sigmoid utility scores and masked
multi-label BCE targets. The optional [local Kev trainer](kev/README.md) warm-starts
the pinned Kev-0.8B adapter and pointer head; its released softmax task is separate
from this utility objective. Native production scoring remains R0.

Generate the built-in local synthetic corpus, then verify it in a fresh process:

```powershell
cargo run -p contextdb-bench --locked --example router_corpus -- build D:/Develop/router-corpus
cargo run -p contextdb-bench --locked --example router_corpus -- verify D:/Develop/router-corpus
```

For complete prepared-state R0 replay, use a separate versioned output profile:

```powershell
cargo run -p contextdb-bench --locked --example router_corpus -- build-replay D:/Develop/router-replay-corpus
cargo run -p contextdb-bench --locked --example router_corpus -- verify-replay D:/Develop/router-replay-corpus
```

For conditional supervision from the compiler's actual selected-base/trial
callbacks, use another output directory:

```powershell
cargo run -p contextdb-bench --locked --example router_corpus -- build-conditional D:/Develop/router-conditional-corpus
cargo run -p contextdb-bench --locked --example router_corpus -- verify-conditional D:/Develop/router-conditional-corpus
```

This profile collects rendered semantic inputs under a fixed, target-independent
selection policy. Separate targets bind each exact callback and measure additional
source coverage relative to its selected base. Already covered sources are
negative; unproven partial complements remain masked. Valid alternative proof
sets use exact source ranges. These labels are a synthetic learning surrogate,
not measured reader utility. Connected histories remain in one fold.

Its four artifacts are `inputs.json`, `observations.json`, `targets.json` and
`lineage.json`, followed by `manifest.json`. The whole generation fails beyond
64 cases, 512 callbacks, 16 proposals per selected base or 64 MiB; it never keeps
only a prefix. Host observations and source identities stay outside model input.

Cold verification regenerates the public fixtures through the same callback path
and compares semantic material, source witnesses and complete encoded wires.
Recorded remaining work, bytes, time and evaluation counters stay in the artifacts;
fresh-run comparison excludes only the declared volatile counters. It does not
reproduce historical elapsed time. The conditional Kev profile refuses the old
initial-context bundle and excludes test/quarantine before Python projection or
model use.

The parent directory must exist. The original and replay directories receive five bounded
artifacts and a final manifest. A completed retry verifies and reuses the same
artifacts; an incomplete directory is preserved and refused. The writer accepts
only built-in synthetic originals. It does not export private native traces.

- `query-time.json`: query, authorized inventory, material and original base.
- `features.json`: verified semantic inputs, excluding R0 utilities and labels.
- `behavior.json`: actual R0 scores, selection, STOP and preparation provenance.
- `targets.json`: independent source-set labels; unknown means masked, not false.
- `lineage.json`: source versions, derivation parents and connected time splits.

IDs, digests and fixture names are association metadata. The Kev input renderer
excludes them and uses opaque candidate slots; serializing this whole record
directly into a training prompt would permit fixture shortcuts.

Four distinct synthetic source groups cover early and corrected facts, a local
constraint, complementary memories, an irrelevant query, Russian/English queries
and fully resident originals. Connected groups stay together; a boundary-crossing
group is quarantined. Labels are synthetic source-set supervision, not measured
reader benefit or calibrated marginal utility. R0 can select irrelevant memories.

The original profile omits prepared policy and cannot reproduce historical
selection. The replay profile retains actual prepared variant costs, generated
markers, ordered omissions, selector allowance and separate attempt observations.
Cold verification executes pinned R0 through the compiler's shared selection and
rendering path and compares exact scores, attempts, closure, support, STOP, pack,
ordered wire and token counts. Each compile reserves 200,000 work units and 16 MiB
from the batch; replay reserves the recorded remaining selector allowance with the
same enclosing deadline and cancellation. Completed retry reuses existing bytes.

Behavior observations and labels never enter the feature builder. The original
corpus and initial-context trainer do not use the live compiler's selected-base/trial
semantic scoring view; calibrated utility remains unavailable in every profile. Synthetic artifacts
have no native acceptance or current source-wire proof. Native v1 refuses prepared
policy extensions. These columns stay separate from historical integrity; hashes
and synthetic markers grant no rights.

The native accepted-trace reader independently checks current capabilities,
purpose, custody and origin controls before returning protected material. It
performs no model call or write and does not grant training or export permission.
The explicit `required_replay_v2` native profile retains full prepared state and
separate behavior observations under encrypted custody. Accepted reads check
current rights and retained metadata; historical selection is unavailable until
the consumer executes detached R0 replay. Real corpus export, training-purpose
admission, learned production rollout and paired memory benchmarks remain later
work. The bounded public synthetic trainer is development infrastructure; its
metrics and cold reload do not establish generalization or reader benefit.
