# Resource quotas and graceful degradation

RFC 25.35 requires workspace/agent limits for storage bytes, daily episodes,
vectors, model cost, concurrent recalls, snapshot age, background CPU, retention
and subscriptions. RFC 25.36 orders degradation so durable raw observations and
exact primary reads survive before approximate/speculative features.

The desired degradation order is:

1. durable raw observations;
2. exact primary reads;
3. working memory/checkpoints;
4. lexical/graph recall;
5. exact vector scan;
6. ANN;
7. summaries;
8. reflection/speculative maintenance.

An exhausted optional budget must produce an explicit bounded partial/degraded
result, queue/backpressure decision, or rejected request. It must not corrupt
primary state, silently broaden policy, loop model retries, or terminate through
uncontrolled OOM.

The current server has one bounded source-level control: HTTP and gRPC share a
single fail-fast blocking-execution admission authority in the production host.
Interactive, bulk-transfer, and maintenance work have independent nonzero
semaphore pools; a permit is acquired before submission to Tokio's blocking
executor and retained until the closure exits. Saturation returns a retryable,
content-free `ResourceExhausted` response and does not queue the service call.
Trusted gateway verification and route-specific capability authorization run
before admission; bounded policy discriminators (hard-delete mode and timeline
record kind) are the only operation fields inspected before that authorization.
Streaming recall reserves its permit before emitting `Started`.
Health probes use their separate one-slot bounded path, so saturated application
work cannot consume liveness capacity. Legacy constructors create conservative
adapter-local defaults; only the production host proves cross-transport sharing.

This is not full operational proof. Capacities are build-time defaults rather
than a validated per-workspace/per-agent quota configuration, and the controller
does not limit accepted TCP connections or bytes already admitted by the 16 MiB
wire guard. Pressure tests, bounded-memory p99, graceful shutdown under ENOSPC,
background CPU scheduling, and structured health fields for every degradation
state remain M16/M17 and RFC 31.12/31.15 gates.
