# Disaster recovery

## Safety order

1. Preserve affected files, logs, version manifest, artifact hashes and incident
   time; do not experiment on the only copy.
2. Stop writers or fence the affected path. Readers may continue only if the
   engine explicitly reports a safe degraded/read-only state.
3. Run shallow/deep verification on a copy and record the report.
4. Select the newest verified backup whose retention/deletion policy permits
   restore. Verify its signature/checksums before decrypting or importing, and
   recover the independently protected external token key without placing it in
   the archive directory. Preserve the current state-head authority as incident
   evidence; do not roll it back with the archive.
5. Clone-import into a fresh isolated directory with a fresh empty external
   state-head authority (`CONTEXTDB_STATE_HEAD_ID` on Windows or an owner-only
   external `CONTEXTDB_STATE_HEAD_FILE` on Unix). `--force` is disabled.
6. Replay/verify, rebuild only derived indexes, compare commit/watermark/policy
   state, and run application probes.
7. Activate the restored path explicitly and retain the failed source according
   to incident and privacy policy.
8. Produce a content-free incident report and test the corrective action.

Corruption must never be converted into silent memory. Unavailable evidence,
damaged ranges and degraded projections remain visible; no watermark advances
beyond an unverified range.

## Recovery objectives

Beta must freeze recovery-time and recovery-point targets on reference hardware.
Until M17 performance and M16 fault/restore gates pass, no numeric RTO/RPO is
claimed here. Sync durability aims at zero acknowledged loss within the declared
fault model, but a source-level journal test is not proof against every platform,
filesystem, hardware or operator failure.

## Required exercise receipt

Record exact artifacts, source/backup/restored digests, non-secret authority
identity/rotation receipt (never authority contents), fault scenario, host and
filesystem, start/end time, last acknowledged commit, restored commit,
watermarks, rebuild actions, policy/deletion checks, probe results, limitations
and operator identity. A tabletop review is manual evidence; a successful
restore is runtime evidence. Both are needed, and neither is publication proof.
