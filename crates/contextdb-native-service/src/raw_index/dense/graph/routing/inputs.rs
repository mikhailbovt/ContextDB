//! Complete directory coverage with only one finite fine path in scratch memory.

use super::super::prefix_segments_v2::types as segment_types;
use super::super::prefix_v2::types as base_types;
use super::super::publication::GraphInput;
use super::super::segments::crypto::{metered_encode, metered_json_len};
use super::proof::{VerifiedRouterDirectory, replay_generation};
use super::*;
use contextdb_recall::QueryLimit;
use std::{
    io::{self, Write},
    mem::size_of,
};

pub(super) struct RouterSourceCheckV1 {
    pub(super) event_id: ObservationId,
    pub(super) policy_domain: String,
}
pub(super) struct DirectoryRouterBuildInputV1 {
    pub(super) inputs: Vec<DirectoryRouterInputV1>,
    pub(super) source_checks: Vec<RouterSourceCheckV1>,
    pub(super) coverage_count: u64,
    pub(super) coverage_digest: ContentDigest,
}

#[derive(Serialize)]
struct CoverageHeader<'a> {
    database_id: &'a str,
    workspace_digest: &'a str,
    raw: &'a PrefixRawBindingV2,
    coverage: &'a DirectoryRouterCoverageV1,
    covered: &'a DenseManifest,
    covered_dense: &'a AcceptedPublicationRef,
    ending: &'a CaptureBoundaryRefV2,
    count: u64,
}
struct CoverageHash {
    hash: blake3::Hasher,
    count: u64,
}
struct Writer<'a> {
    parent: &'a mut QueryBudget,
    hash: &'a mut blake3::Hasher,
    failure: Option<QueryLimit>,
}
impl Write for Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::Error::other("router stream ended"));
        }
        if let Err(error) = self
            .parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 2)
        {
            self.failure = Some(error);
            return Err(io::Error::other("router parent refused"));
        }
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_some() {
            return Err(io::Error::other("router stream ended"));
        }
        if let Err(error) = self.parent.check() {
            self.failure = Some(error);
            return Err(io::Error::other("router parent refused"));
        }
        Ok(())
    }
}
impl CoverageHash {
    fn new(header: CoverageHeader<'_>, parent: &mut QueryBudget) -> ServiceResult<Self> {
        parent
            .charge(1, size_of::<Self>() as u64 + 256)
            .map_err(budget_error)?;
        let mut value = Self {
            hash: blake3::Hasher::new(),
            count: 0,
        };
        let mut writer = Writer {
            parent,
            hash: &mut value.hash,
            failure: None,
        };
        let result = writer.write_all(COVERAGE_DOMAIN);
        if let Some(error) = writer.failure {
            return Err(budget_error(error));
        }
        result.map_err(|_| integrity("router coverage domain failed"))?;
        value.part(&header, parent)?;
        Ok(value)
    }
    fn part<T: Serialize>(&mut self, part: &T, parent: &mut QueryBudget) -> ServiceResult<()> {
        let mut writer = Writer {
            parent,
            hash: &mut self.hash,
            failure: None,
        };
        let result = serde_json::to_writer(&mut writer, part);
        if let Some(error) = writer.failure {
            return Err(budget_error(error));
        }
        result.map_err(|_| integrity("router coverage encoding failed"))?;
        let result = writer.write_all(&[0]);
        if let Some(error) = writer.failure {
            return Err(budget_error(error));
        }
        result.map_err(|_| integrity("router coverage separator failed"))
    }
    fn path<T: Serialize>(
        &mut self,
        path: &DirectoryRouterFinePathV1,
        manifest: &T,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let count = self
            .count
            .checked_add(1)
            .ok_or_else(|| exhausted("router coverage count overflow"))?;
        self.part(&(path, manifest), parent)?;
        self.count = count;
        Ok(())
    }
}

enum FineManifest<'a> {
    Base(&'a base_types::DensePrefixBaseManifestV2),
    Segment(&'a segment_types::PrefixDeltaManifestV2),
}

impl NativeService {
    pub(super) fn router_build_input<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        proof: &VerifiedRouterDirectory,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterBuildInputV1> {
        parent.check().map_err(budget_error)?;
        match (context, proof.context_binding()) {
            (Some(context), Some(binding))
                if crate::budgeted::auth::binding_digest(context, parent)? == binding => {}
            (None, None) if proof.world().is_none() => {}
            _ => return Err(integrity("router replay authority/context differs")),
        }
        let workspace = digest_bytes(proof.base().workspace_id.as_bytes());
        self.router_input_fence(context, proof, parent)?;
        let raw = PrefixRawBindingV2::from_generation(proof.generation(), parent)?;
        let count = proof.coverage().count()?;
        let mut hash = CoverageHash::new(
            CoverageHeader {
                database_id: &self.database_id,
                workspace_digest: &workspace,
                raw: &raw,
                coverage: proof.coverage(),
                covered: proof.covered(),
                covered_dense: proof.covered_dense(),
                ending: proof.ending(),
                count,
            },
            parent,
        )?;
        parent
            .charge(
                1,
                MAX_REPRESENTATIVES as u64 * size_of::<DirectoryRouterInputV1>() as u64 + 4096,
            )
            .map_err(budget_error)?;
        let mut representatives = Vec::with_capacity(MAX_REPRESENTATIVES);
        let mut sources = BTreeMap::<ObservationId, String>::new();
        let mut policies = BTreeMap::<String, Vec<AccessPolicy>>::new();

        let base = proof.base();
        router_path_capacity(
            &base.manifest.cohorts,
            representatives.len(),
            &policies,
            parent,
        )?;
        let target = self.verify_accepted_prefix_dense_target(
            snapshot,
            &workspace,
            &base.manifest.target,
            parent,
        )?;
        let frozen = replay_generation(&base.manifest.raw, &base.manifest.prefix, None, parent)?;
        let mut input =
            self.prefix_build_input(snapshot, context, &workspace, &frozen, &target, parent)?;
        if input.interval != base.manifest.interval {
            return Err(integrity("router base complete replay differs"));
        }
        let bytes = metered_json_len(&base.manifest, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 32 + 8192)
            .map_err(budget_error)?;
        let mut manifest = base.manifest.clone();
        let rows =
            self.construct_prefix_base(&workspace, &frozen, &mut manifest, &input.inputs, parent)?;
        if manifest != base.manifest {
            return Err(integrity("router entire base topology differs"));
        }
        self.router_fine_rows(
            snapshot,
            context,
            proof,
            &workspace,
            &frozen,
            FineManifest::Base(&manifest),
            &input.inputs,
            rows,
            parent,
        )?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        self.router_fine_receipt(
            snapshot,
            &base_types::receipt_key(&workspace, frozen.number)?,
            base,
            parent,
        )?;
        parent.charge(1, 4096).map_err(budget_error)?;
        let path = DirectoryRouterFinePathV1::Base {
            base: proof.coverage().base.clone(),
        };
        hash.path(&path, &manifest, parent)?;
        self.router_path_representatives(
            &workspace,
            proof.generation(),
            path,
            &manifest.cohorts,
            &mut input.inputs,
            &mut representatives,
            &mut sources,
            &mut policies,
            parent,
        )?;
        drop(input);
        let mut previous: Option<segment_types::PrefixSegmentPublicationV2> = None;
        if let Some(head) = proof.head() {
            for ordinal in 1..=head.directory.head.count {
                self.router_input_fence(context, proof, parent)?;
                let publication = self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    &workspace,
                    proof.generation().number,
                    ordinal,
                    parent,
                )?;
                self.check_prefix_segment_generation_binding(
                    snapshot,
                    &workspace,
                    proof.generation(),
                    &publication,
                    parent,
                )?;
                if let Some(previous) = &previous {
                    self.check_prefix_interval_predecessor(
                        snapshot,
                        previous,
                        &publication,
                        parent,
                    )?;
                } else if publication.delta.manifest.before != base.manifest.prefix
                    || publication.delta.manifest.before_dense != base.manifest.target
                    || publication.delta.manifest.base != proof.coverage().base
                    || publication.directory.head.previous.is_some()
                {
                    return Err(integrity("router first interval differs from genuine base"));
                }
                let accepted = &publication.delta.manifest;
                router_path_capacity(&accepted.cohorts, representatives.len(), &policies, parent)?;
                let before = self.verify_prefix_segment_dense_state(
                    snapshot,
                    &workspace,
                    &accepted.before_dense,
                    parent,
                )?;
                let after = self.verify_prefix_segment_dense_state(
                    snapshot,
                    &workspace,
                    &accepted.target_dense,
                    parent,
                )?;
                if before.manifest() != &accepted.before || after.manifest() != &accepted.after {
                    return Err(integrity("router interval dense acceptance differs"));
                }
                let start = self.verify_prefix_segment_capture_boundary(
                    snapshot,
                    &workspace,
                    &accepted.start,
                    parent,
                )?;
                if ordinal == 1 {
                    let actual = self.first_prefix_segment_capture_boundary(
                        snapshot, &workspace, &target, parent,
                    )?;
                    if actual.reference() != start.reference() {
                        return Err(integrity("router first interval capture boundary differs"));
                    }
                }
                let interval = self.verify_prefix_segment_interval(
                    snapshot, &workspace, before, after, start, parent,
                )?;
                if interval.end().reference() != &accepted.end {
                    return Err(integrity("router interval ending differs"));
                }
                let base_ref = self.prefix_base_reference(snapshot, base, parent)?;
                let frozen =
                    replay_generation(&accepted.raw, &accepted.after, Some(&base_ref), parent)?;
                let mut input = self.prefix_segment_build_input(
                    snapshot,
                    context,
                    &workspace,
                    &frozen,
                    &accepted.base,
                    &interval,
                    parent,
                )?;
                if input.interval != accepted.interval {
                    return Err(integrity("router complete interval digest differs"));
                }
                let bytes = metered_json_len(accepted, parent, ROW_BYTES)?;
                parent
                    .charge(bytes as u64 + 1, bytes as u64 * 32 + 8192)
                    .map_err(budget_error)?;
                let mut manifest = accepted.clone();
                let rows = self.construct_prefix_segment(
                    &workspace,
                    &frozen,
                    &mut manifest,
                    &input.inputs,
                    parent,
                )?;
                if &manifest != accepted {
                    return Err(integrity("router entire interval topology differs"));
                }
                self.router_fine_rows(
                    snapshot,
                    context,
                    proof,
                    &workspace,
                    &frozen,
                    FineManifest::Segment(&manifest),
                    &input.inputs,
                    rows,
                    parent,
                )?;
                parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                self.router_fine_receipt(
                    snapshot,
                    &segment_types::delta_receipt_key(&workspace, frozen.number, ordinal)?,
                    &publication.delta,
                    parent,
                )?;
                let encoded = metered_encode(&publication.delta, parent, ROW_BYTES)?;
                parent
                    .charge(encoded.len() as u64 + 1, 4096)
                    .map_err(budget_error)?;
                let path = DirectoryRouterFinePathV1::Segment {
                    ordinal,
                    publication: self.prefix_publication_ref(
                        snapshot,
                        publication.delta.global_commit,
                        parent,
                    )?,
                    receipt_digest: digest(&encoded),
                    content_digest: accepted.content_digest,
                };
                hash.path(&path, &manifest, parent)?;
                self.router_path_representatives(
                    &workspace,
                    proof.generation(),
                    path,
                    &manifest.cohorts,
                    &mut input.inputs,
                    &mut representatives,
                    &mut sources,
                    &mut policies,
                    parent,
                )?;
                previous = Some(publication);
            }
            if previous.as_ref() != Some(head) {
                return Err(integrity("router complete scan ends at another directory"));
            }
        }
        self.router_input_fence(context, proof, parent)?;
        if hash.count != count || representatives.is_empty() {
            return Err(integrity("router complete coverage cardinality differs"));
        }
        parent
            .charge(
                sources.len() as u64 + 1,
                sources.len() as u64 * size_of::<RouterSourceCheckV1>() as u64 + 256,
            )
            .map_err(budget_error)?;
        let mut source_checks = Vec::with_capacity(sources.len());
        for (event_id, policy_domain) in sources {
            source_checks.push(RouterSourceCheckV1 {
                event_id,
                policy_domain,
            });
        }
        parent.charge(1, 256).map_err(budget_error)?;
        Ok(DirectoryRouterBuildInputV1 {
            inputs: representatives,
            source_checks,
            coverage_count: hash.count,
            coverage_digest: ContentDigest::from_bytes(*hash.hash.finalize().as_bytes()),
        })
    }

    pub(super) fn router_input_fence(
        &self,
        context: Option<&AuthenticatedRequestContext>,
        proof: &VerifiedRouterDirectory,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        let Some(context) = context else {
            return Ok(());
        };
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        parent.charge(1, KEY_BYTES * 2).map_err(budget_error)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let state: IndexState = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let generation: Generation = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &generation_key(&workspace, proof.generation().number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let world =
            self.current_directory_router_heads(&current, &context.request.workspace_id, parent)?;
        if state.active != Some(generation.number)
            || &generation != proof.generation()
            || Some(&world) != proof.world()
            || self.graph_epoch(&current, &workspace, parent)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        crate::budgeted::metadata(&current, parent, |reader| {
            self.require_custody_ready(reader, &workspace)
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one path scratch and the shared parent stay explicit"
    )]
    fn router_fine_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        proof: &VerifiedRouterDirectory,
        workspace: &str,
        frozen: &Generation,
        manifest: FineManifest<'_>,
        inputs: &[GraphInput],
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent
            .charge(
                inputs.len() as u64 + 1,
                (inputs.len() as u64 + 1)
                    * (12 * size_of::<(RepresentationId, &GraphInput)>() as u64 + 256),
            )
            .map_err(budget_error)?;
        let mut members = BTreeMap::new();
        for input in inputs {
            let bytes = metered_json_len(&input.vector, parent, ROW_BYTES)?;
            parent
                .charge(bytes as u64 + 1, bytes as u64 * 4 + 2048)
                .map_err(budget_error)?;
            let (_, id) = identity(&self.database_id, workspace, frozen.number, &input.vector)?;
            if members.insert(id, input).is_some() {
                return Err(integrity("router fine identity collision"));
            }
        }
        for (key, expected) in rows {
            self.router_input_fence(context, proof, parent)?;
            parent
                .charge(
                    key.len() as u64 + expected.len() as u64 + 1,
                    expected.len() as u64 * 16 + 8192,
                )
                .map_err(budget_error)?;
            let text = std::str::from_utf8(&key)
                .map_err(|_| integrity("router fine canonical key is not UTF8"))?;
            let (id, domain) = match &manifest {
                FineManifest::Base(manifest) if text.contains("/member/") => {
                    let row: base_types::PrefixMemberV2 =
                        decode(&expected, "router expected base member")?;
                    self.check_prefix_member(workspace, manifest, &row, parent)?;
                    (Some(row.representation_id), row.policy_domain)
                }
                FineManifest::Segment(manifest) if text.contains("/member/") => {
                    let row: segment_types::PrefixSegMemberV2 =
                        decode(&expected, "router expected interval member")?;
                    self.check_prefix_segment_member(workspace, manifest, &row, parent)?;
                    (Some(row.representation_id), row.policy_domain)
                }
                FineManifest::Base(manifest) if text.contains("/node/") => {
                    let row: base_types::PrefixNodeV2 =
                        decode(&expected, "router expected base node")?;
                    let node = self.check_prefix_node(workspace, manifest, &row, parent)?;
                    (Some(node.representation_id), row.policy_domain)
                }
                FineManifest::Segment(manifest) if text.contains("/node/") => {
                    let row: segment_types::PrefixSegNodeV2 =
                        decode(&expected, "router expected interval node")?;
                    let node = self.check_prefix_segment_node(workspace, manifest, &row, parent)?;
                    (Some(node.representation_id), row.policy_domain)
                }
                FineManifest::Base(manifest) if text.contains("/cohort/") => {
                    let row: base_types::PrefixCohortV2 =
                        decode(&expected, "router expected base cohort")?;
                    self.check_prefix_cohort(workspace, manifest, &row, parent)?;
                    (None, row.policy_domain)
                }
                FineManifest::Segment(manifest) if text.contains("/cohort/") => {
                    let row: segment_types::PrefixSegCohortV2 =
                        decode(&expected, "router expected interval cohort")?;
                    self.check_prefix_segment_cohort(workspace, manifest, &row, parent)?;
                    (None, row.policy_domain)
                }
                _ => return Err(integrity("router constructed unknown fine row")),
            };
            match id {
                Some(id) => {
                    let input = members
                        .get(&id)
                        .ok_or_else(|| integrity("router fine node has no genuine source"))?;
                    if input.vector.policy_domain != domain {
                        return Err(integrity("router fine node cohort differs"));
                    }
                    self.admit_prefix_source(
                        context,
                        workspace,
                        frozen,
                        input.vector.source.event_id,
                        parent,
                    )?;
                }
                None => {
                    let mut found = false;
                    for input in inputs {
                        parent.charge(1, 0).map_err(budget_error)?;
                        if input.vector.policy_domain == domain {
                            self.admit_prefix_source(
                                context,
                                workspace,
                                frozen,
                                input.vector.source.event_id,
                                parent,
                            )?;
                            found = true;
                        }
                    }
                    if !found {
                        return Err(integrity("router fine cohort has no admitted contributors"));
                    }
                }
            }
            let actual = crate::budgeted::read_value(
                snapshot,
                &self.keyspaces.continuous,
                &key,
                ROW_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("router actual canonical fine row is absent"))?;
            if actual != expected {
                return Err(integrity("router actual canonical fine row differs"));
            }
        }
        Ok(())
    }

    fn router_fine_receipt<S: ReadSnapshot, T: Serialize>(
        &self,
        snapshot: &S,
        key: &[u8],
        receipt: &T,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let expected = metered_encode(receipt, parent, ROW_BYTES)?;
        let actual = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.continuous,
            key,
            ROW_BYTES,
            parent,
        )?
        .ok_or_else(|| integrity("router actual fine receipt is absent"))?;
        if actual != expected {
            return Err(integrity("router actual fine receipt differs"));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one path feeds complete bounded representatives and final CAS suppliers"
    )]
    fn router_path_representatives(
        &self,
        workspace: &str,
        generation: &Generation,
        path: DirectoryRouterFinePathV1,
        summaries: &[GraphCohortSummary],
        inputs: &mut [GraphInput],
        representatives: &mut Vec<DirectoryRouterInputV1>,
        sources: &mut BTreeMap<ObservationId, String>,
        policies: &mut BTreeMap<String, Vec<AccessPolicy>>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        router_path_capacity(summaries, representatives.len(), policies, parent)?;
        let levels = usize::BITS - inputs.len().saturating_add(1).leading_zeros();
        parent
            .charge((inputs.len() as u64 + 1) * u64::from(levels + 1) * 8192, 0)
            .map_err(budget_error)?;
        inputs.sort_unstable_by(|a, b| {
            a.vector
                .policy_domain
                .cmp(&b.vector.policy_domain)
                .then(a.vector.source.event_id.cmp(&b.vector.source.event_id))
                .then(a.vector.ordinal.cmp(&b.vector.ordinal))
        });
        let mut offset: usize = 0;
        for summary in summaries {
            let size = usize::try_from(summary.nodes)
                .map_err(|_| exhausted("router fine node count overflow"))?;
            let end = offset
                .checked_add(size)
                .filter(|end| *end <= inputs.len())
                .ok_or_else(|| integrity("router fine cohort count differs from actual vectors"))?;
            let group = &inputs[offset..end];
            if group.is_empty()
                || group
                    .iter()
                    .any(|i| i.vector.policy_domain != summary.policy_domain)
            {
                return Err(integrity(
                    "router fine cohort does not contain every exact vector",
                ));
            }
            let first = &group[0];
            if let Some(known) = policies.get(&summary.policy_domain) {
                let bytes = metered_json_len(&first.policies, parent, ROW_BYTES)?;
                parent.charge(bytes as u64 + 1, 0).map_err(budget_error)?;
                if known != &first.policies {
                    return Err(integrity("router compound policy domain aliases labels"));
                }
            } else {
                if policies.len() == MAX_COHORTS {
                    return Err(exhausted("router complete directory exceeds 64 policies"));
                }
                let bytes = metered_json_len(&first.policies, parent, ROW_BYTES)?;
                parent
                    .charge(bytes as u64 + 1, bytes as u64 * 16 + 32768)
                    .map_err(budget_error)?;
                policies.insert(summary.policy_domain.clone(), first.policies.clone());
            }
            for input in group {
                parent.charge(1, 0).map_err(budget_error)?;
                match sources.get(&input.vector.source.event_id) {
                    Some(domain) if domain != &input.vector.policy_domain => {
                        return Err(integrity("router supplier aliases a policy domain"));
                    }
                    Some(_) => {}
                    None => {
                        let levels = u64::from(
                            usize::BITS - sources.len().saturating_add(1).leading_zeros(),
                        ) + 2;
                        parent
                            .charge(
                                levels * 12,
                                levels * (12 * size_of::<(ObservationId, String)>() as u64 + 1024),
                            )
                            .map_err(budget_error)?;
                        sources.insert(
                            input.vector.source.event_id,
                            input.vector.policy_domain.clone(),
                        );
                    }
                }
            }
            parent.charge(1, 8192).map_err(budget_error)?;
            let representative = self.directory_router_input(
                workspace,
                generation,
                path.clone(),
                summary.partition_digest,
                &first.policies,
                group,
                parent,
            )?;
            if representative.contributors != summary.nodes
                || representative.policy_domain != summary.policy_domain
            {
                return Err(integrity(
                    "router representative lost exact fine cohort members",
                ));
            }
            representatives.push(representative);
            offset = end;
        }
        if offset != inputs.len() {
            return Err(integrity(
                "router fine vectors were omitted from complete coverage",
            ));
        }
        Ok(())
    }
}

fn router_path_capacity(
    summaries: &[GraphCohortSummary],
    representatives: usize,
    policies: &BTreeMap<String, Vec<AccessPolicy>>,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    parent
        .charge(summaries.len() as u64 * 128 + 1, 0)
        .map_err(budget_error)?;
    if summaries.len() > MAX_COHORTS
        || representatives
            .checked_add(summaries.len())
            .is_none_or(|n| n > MAX_REPRESENTATIVES)
    {
        return Err(exhausted(
            "router complete representative/cohort capacity exceeded",
        ));
    }
    let new_domains = summaries
        .iter()
        .filter(|summary| !policies.contains_key(&summary.policy_domain))
        .count();
    if policies
        .len()
        .checked_add(new_domains)
        .is_none_or(|n| n > MAX_COHORTS)
    {
        return Err(exhausted(
            "router complete directory exceeds 64 compound cohorts",
        ));
    }
    Ok(())
}
