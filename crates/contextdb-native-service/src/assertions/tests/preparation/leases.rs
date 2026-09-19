use super::*;
use contextdb_service::{ContextLeasePort, ContextLeaseStatus};

#[test]
fn native_lease_rejects_changed_scope_before_registration_and_notices_new_negative_state() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "lease", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let context = request(&input).context;
    let prepared = prepare(&service, request(&input)).expect("prepare");
    let lease = service
        .register_context_lease(&context, &prepared, &mut allowance())
        .expect("register");
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("status"),
        ContextLeaseStatus::Current
    );
    let mut other = capture(2, "An unrelated observation in another scope.");
    let other_scope = ScopeId::new();
    other.event.scope_ids = BTreeSet::from([other_scope]);
    other.context.request.scopes = BTreeSet::from([other_scope.to_string()]);
    other.context.request.purpose = "conversation".into();
    service.append_event(other).expect("independent scope");
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("unaffected scope"),
        ContextLeaseStatus::Current
    );
    let mut prohibited = capture(3, "New prohibition in the subscribed scope.");
    prohibited.context.request.purpose = "conversation".into();
    service
        .append_event(prohibited)
        .expect("new constraint before interpretation");
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("coalesced notification"),
        ContextLeaseStatus::Invalidated
    );
    assert_eq!(
        service
            .register_context_lease(&context, &prepared, &mut allowance())
            .expect_err("lost watcher race rejected")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn concurrent_registration_and_capture_cannot_leave_a_current_stale_lease() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = Arc::new(NativeService::open(directory.path(), "lease", [7; 32]).expect("open"));
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let context = request(&input).context;
    let prepared = prepare(&service, request(&input)).expect("prepare");
    let barrier = Arc::new(Barrier::new(3));
    let (registered, captured) = std::thread::scope(|threads| {
        let registration = threads.spawn(|| {
            barrier.wait();
            service.register_context_lease(&context, &prepared, &mut allowance())
        });
        let capture = threads.spawn(|| {
            barrier.wait();
            let mut event = capture(2, "A constraint racing with registration.");
            event.context.request.purpose = "conversation".into();
            service.append_event(event)
        });
        barrier.wait();
        (
            registration.join().expect("register thread"),
            capture.join().expect("capture thread"),
        )
    });
    captured.expect("writer committed");
    match registered {
        Ok(lease) => assert_eq!(
            service
                .context_lease_status(&context, &lease, &mut allowance())
                .expect("status after joined writer"),
            ContextLeaseStatus::Invalidated
        ),
        Err(error) => assert_eq!(error.code, ErrorCode::IndexTooStale),
    }
}

#[test]
fn preparation_seal_policy_revocation_and_process_restart_are_enforced() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "lease", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let context = request(&input).context;
    let prepared = prepare(&service, request(&input)).expect("prepare");
    let mut forged = prepared.clone();
    forged.outgoing.wire.push(b' ');
    assert_eq!(
        service
            .register_context_lease(&context, &forged, &mut allowance())
            .expect_err("changed wire")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut forged = prepared.clone();
    forged.assembly.read_set.originals.clear();
    assert_eq!(
        service
            .register_context_lease(&context, &forged, &mut allowance())
            .expect_err("omitted dependency")
            .code,
        ErrorCode::InvalidArgument
    );
    let lease = service
        .register_context_lease(&context, &prepared, &mut allowance())
        .expect("register");
    let mut foreign = context.clone();
    foreign.request.purpose = "another-purpose".into();
    assert_eq!(
        service
            .context_lease_status(&foreign, &lease, &mut allowance())
            .expect_err("principal binding")
            .code,
        ErrorCode::PermissionDenied
    );
    service
        .revoke_original(
            &context,
            input.event.event_id,
            "revoke-lease-source",
            &mut allowance(),
        )
        .expect("revoke");
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("revoked"),
        ContextLeaseStatus::Invalidated
    );
    drop(service);
    let service = NativeService::open(directory.path(), "lease", [7; 32]).expect("reopen");
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("restart"),
        ContextLeaseStatus::Expired
    );
    assert_eq!(
        service
            .register_context_lease(&context, &prepared, &mut allowance())
            .expect_err("old issuer")
            .code,
        ErrorCode::ContinuationExpired
    );
}

#[test]
fn temporal_lease_expires_without_a_new_write_and_cannot_be_registered_again() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "lease", [7; 32]).expect("open");
    let mut input = capture(1, "Permission expires at its explicit validity boundary.");
    input.context.request.purpose = "conversation".into();
    service.append_event(input.clone()).expect("original");
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_micros() as i64
        + 5_000_000;
    let mut asserted = assertion(&input, "temporary permission", 0, Some(expires), vec![]);
    asserted.revision.envelope.ownership.allowed_purposes = BTreeSet::from([Purpose::Conversation]);
    publish(
        &service,
        &input,
        "temporary",
        vec![
            AssertionMutation::Policy {
                policy: policy(&input),
            },
            change(asserted),
        ],
    );
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let context = request(&input).context;
    let prepared = prepare(&service, request(&input)).expect("prepare");
    let lease = service
        .register_context_lease(&context, &prepared, &mut allowance())
        .expect("register before boundary");
    assert_eq!(lease.valid_until, TimestampMicros(expires));
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read");
    let head = service
        .workspace_state(&before, &context.request.workspace_id)
        .expect("head")
        .watermarks
        .journal;
    drop(before);
    let current = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_micros() as i64;
    std::thread::sleep(Duration::from_micros(
        u64::try_from((expires - current).max(0)).expect("remaining") + 10_000,
    ));
    assert_eq!(
        service
            .context_lease_status(&context, &lease, &mut allowance())
            .expect("expiry"),
        ContextLeaseStatus::Expired
    );
    assert_eq!(
        service
            .register_context_lease(&context, &prepared, &mut allowance())
            .expect_err("cannot extend old applicability")
            .code,
        ErrorCode::ContinuationExpired
    );
    let refreshed = prepare(&service, request(&input)).expect("refresh applicability");
    assert!(
        refreshed.context_pack.sections.decisions.is_empty(),
        "expired permission is not current"
    );
    service
        .register_context_lease(&context, &refreshed, &mut allowance())
        .expect("new view after boundary");
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read");
    assert_eq!(
        service
            .workspace_state(&after, &context.request.workspace_id)
            .expect("head")
            .watermarks
            .journal,
        head
    );
}
