# Continuous context: final benchmark stage

**Phase 17 — planned, not executed.** Added to the implementation plan on
20 September 2026 at the user's request. This is the required final evaluation
of the integrated phases 00–15. Optional phase 16 is not a dependency. These
phase numbers are separate from the original M0–M19 release milestone ledger.

## Benchmark scope

| Suite | Required evaluation |
| --- | --- |
| [MemGym](https://github.com/WujiangXu/MemGym) | Same agent/model without and with ContextDB on MemGym-DR, CodeQA and a real action track, initially SWE-Gym. Use actual task validators; MemRM is supplementary evidence. Register any additional tau2/WebArena tracks before the final run. |
| [MemoryGym](https://github.com/Evilander/memorygym) | Adapter regression suite for updates, stale variants, context routing and abstention. Add a paired reader evaluation over the same scenarios, clearly labeled a ContextDB extension; the upstream adapter score alone is not a model comparison. |
| [LongMemEval](https://github.com/xiaowu0162/LongMemEval) | Cleaned S and M splits: extraction, cross-session reasoning, updates, temporal reasoning and abstention. Retain official scoring and per-ability results. |
| [LongMemEval-V2](https://github.com/xiaowu0162/LongMemEval-V2) | Agent-history evidence retrieval and downstream answers; small tier required, medium tier for scale evaluation. Preserve the pinned tier's required modalities and report accuracy/latency separately from conversational QA. |
| [LoCoMo](https://github.com/snap-research/locomo) and [LoCoMo-Plus](https://github.com/xjtuleeyf/Locomo-Plus) | Long conversations, multi-hop/temporal questions and implicit cue-to-constraint recall. Separate official metrics from custom evidence and constraint checks. |
| Held-out ContextDB RU/EN scenarios | Old jokes, incidental details, exact quotes/numbers, corrections, prohibitions, distractors, multiple window rotations, restart/model switch and revoked/deleted originals. Include real tool outcomes and query-time permission changes. |

MemGym and MemoryGym are distinct projects. Pin each upstream revision, dataset
version, permitted use, split and evaluation protocol in the run manifest. Run
the complete frozen test split of each required track, not a convenient demo
subset. Missing data, rights, environments or modalities remain explicit open
gates; altered protocols and omitted tracks cannot inherit an official score.

## Comparison matrix

The headline pair is **the same model without ContextDB vs with ContextDB**.
Use at least two reader profiles: a compact local model and a stronger model,
with exact versions frozen before evaluation. Within each pair preserve the
agent scaffold, task instructions, available non-memory tools, initial environment,
sampling settings, input/output limits, action limits and time budget. Only the
memory/context-management path changes. Disable hidden provider-side memory.

Required arms are vanilla bounded history, a good rolling summary, summary plus
archive/hybrid retrieval, raw hybrid retrieval, ContextDB R0 and the final frozen
ContextDB router. Document the vanilla agent's normal context-overflow policy;
do not manufacture a weak baseline by disabling its standard behavior. Include
full-history context where it fits as a separate reference. Charge every arm's
memory-building, summarization and retrieval work. An oracle-evidence arm may
diagnose reading errors but is never a competing product result.

QA arms receive identical permitted histories at the same query cutoff. Gold
answers, support annotations and future events stay evaluator-only. Action tasks
start from independently reset environments and execute their own trajectories;
one arm cannot reuse another arm's tool outcomes. Reset persistent memory and
cache between independent tasks/arms; measure cold and permitted warm runs
separately. No manual memory selection or per-question prompt repair is allowed.

## Measurement and validity

- Report official task/answer scores, complete required-source coverage, citation
  accuracy, stale-answer and fabricated-answer rates, abstention and constraint
  violations. Break down performance by suite, model, task family, history length,
  evidence age and context budget; separate retrieval, packing and reading errors.
- Measure full attempted-run cost and cost per successful task: reader/router,
  extraction, embeddings, summaries, index construction/maintenance, retries and
  evaluator cost. Record fresh/cached input, output/reasoning, wall time, p50/p95
  latency, peak RAM/VRAM and storage growth. Price assumptions are explicit;
  unavailable money/energy counters are unknown, not zero.
- Freeze train/development/test separation by conversation, project and time.
  The existing phase 09 histories are regression data, not unseen test evidence.
  Freeze router weights and disable online learning during final evaluation.
  Use at least three seeds for stochastic runs, paired confidence intervals with
  task/conversation-level clustering, and publish every failure and timeout.
- Use official evaluators where applicable; pin judge model/prompt and retain
  blinded adjudication of a preregistered disagreement sample. Learned reward or
  judge scores do not replace executable success and exact-source checks.

## Execution and completion

1. Build thin adapters and verify capture, source separation, budgets and result
   accounting on a small development smoke run. No benchmark completion claim.
2. Freeze a manifest with revisions/hashes, exact task IDs, model/reader settings,
   environments, seeds, suite coverage, primary metrics, quality/non-inferiority
   margins, latency/cost limits and bounded compute/retry budgets. Set numeric
   acceptance thresholds before inspecting final outcomes.
3. Execute the paired matrix on the frozen test data. Record requested, attempted,
   completed, failed and unstarted tasks; do not silently shrink denominators or
   tune against the final set. Model/task changes require a new experiment version.
4. Publish a concise comparative report and reproducible machine-readable results,
   commands, manifests and artifact hashes. Keep datasets, weights and bulky logs
   outside the source tree, preferably on D:, with reproducible fetch instructions
   and access-controlled raw artifacts where required.

Execution completion and release acceptance are separate statuses. The phase
passes only with the complete required report and its preregistered gates met;
negative results are published and failed quality/correctness gates remain open.
Report whether ContextDB improves over both vanilla and the stronger baselines,
including workloads where it loses. No benchmark aggregate can waive privacy,
source retention, deletion, freshness or authorized-action invariants. Finite
benchmarks support their tested profiles and do not prove infinite context.
