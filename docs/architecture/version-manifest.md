# Version manifest contract

Every binary, portable archive, benchmark result, debug bundle, and release artifact identifies the exact code, formats, feature profile, and build environment that produced it. The canonical machine schema is [`assets/schemas/version-manifest.schema.json`](../../assets/schemas/version-manifest.schema.json).

The manifest is descriptive, not an authorization token. Sensitive deployment identifiers and credentials never belong in it.

Required compatibility behavior:

- readers reject unknown required format features;
- writers emit exactly one current writer version per format family;
- reader ranges are explicit and inclusive;
- a dirty worktree is visible and cannot produce an official signed release;
- benchmark manifests include the same version object or its content digest;
- feature flags and named distribution profile are recorded separately;
- migration IDs and rollback compatibility are recorded when applicable.

See [`examples/version-manifest.json`](examples/version-manifest.json) for a schema-valid, non-release example.
