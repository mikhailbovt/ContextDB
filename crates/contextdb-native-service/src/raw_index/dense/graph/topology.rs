//! Shared finite ANN topology; receipt and row ownership remain separate.
use super::publication::GraphInput;
use super::*;

use contextdb_index::{
    AnnNodeV2, AnnPartitionBuildBudgetV2, AnnPartitionBuildErrorV2, AnnPartitionBuildInputV2,
    AnnPartitionBuildSpecV2, build_ann_partition_v2,
};

struct BuildBudget<'a>(&'a mut QueryBudget);
impl AnnPartitionBuildBudgetV2 for BuildBudget<'_> {
    type Error = ServiceError;
    fn charge(&mut self, work: u64, bytes: u64) -> ServiceResult<()> {
        self.0.charge(work, bytes).map_err(budget_error)
    }
}
pub(super) struct GraphTopology {
    pub(super) members: Vec<GraphMember>,
    pub(super) cohorts: Vec<GraphCohort>,
    pub(super) nodes: Vec<GraphNode>,
    pub(super) summaries: Vec<GraphCohortSummary>,
}

impl NativeService {
    pub(super) fn construct_graph_topology(
        &self,
        workspace: &str,
        generation: &Generation,
        dense: &DenseManifest,
        inputs: &[GraphInput],
        budget: &mut QueryBudget,
    ) -> ServiceResult<GraphTopology> {
        if inputs.len() > MAX_NODES {
            return Err(exhausted("native graph node cap exceeded"));
        }
        let mut groups = BTreeMap::<String, Vec<(GraphMember, &GraphInput)>>::new();
        let mut ids = BTreeSet::new();
        for input in inputs {
            budget.charge(1, 4096).map_err(budget_error)?;
            let (full, id) = identity(
                &self.database_id,
                workspace,
                generation.number,
                &input.vector,
            )?;
            if !ids.insert(id) {
                return Err(integrity("native graph representation collision"));
            }
            let v = &input.vector;
            let member = GraphMember {
                representation_id: id,
                identity_digest: full,
                source: v.source.clone(),
                event_digest: v.event_digest,
                commit: v.commit,
                ordinal: v.ordinal,
                span: v.span.clone(),
                policy_domain: v.policy_domain.clone(),
                profile_digest: v.profile_digest,
                vector_digest: v.vector_digest,
                graph_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            };
            groups
                .entry(v.policy_domain.clone())
                .or_default()
                .push((member, input));
            if groups.len() > MAX_COHORTS {
                return Err(exhausted("native graph cohort cap exceeded"));
            }
        }
        let space = vector_space(dense);
        let mut cohorts = Vec::new();
        let mut nodes = Vec::new();
        let mut members = Vec::new();
        let mut summaries = Vec::new();
        for (domain, mut group) in groups {
            budget
                .charge(group.len() as u64 * 16 + 1, group.len() as u64 * 64)
                .map_err(budget_error)?;
            group.sort_by_key(|(m, _)| m.representation_id);
            let policies = group[0].1.policies.clone();
            if group.iter().any(|(_, i)| i.policies != policies)
                || canonical_digest(&policies)? != domain
            {
                return Err(integrity("graph compound policy collision"));
            }
            let policy = *blake3::Hash::from_hex(&domain)
                .map_err(ann_error)?
                .as_bytes();
            let args: Vec<_> = group
                .iter()
                .map(|(m, i)| AnnPartitionBuildInputV2 {
                    representation_id: m.representation_id,
                    values: &i.values,
                })
                .collect();
            let built = build_ann_partition_v2(
                &mut BuildBudget(budget),
                &space,
                AnnPartitionBuildSpecV2 {
                    generation: generation.number,
                    policy_digest: policy,
                    membership_epoch: portable_epoch(generation.authorization_epoch)?,
                    global_leaf_index: cohorts.len() as u64,
                    valid_for_all_from: TimestampMicros(i64::MIN),
                    valid_for_all_until: None,
                    parameters: parameters(),
                },
                &args,
            )
            .map_err(|e| match e {
                AnnPartitionBuildErrorV2::Budget(e) => e,
                other => ann_error(other),
            })?;
            let partition = built.partition.encode_json().map_err(ann_error)?;
            summaries.push(GraphCohortSummary {
                policy_domain: domain.clone(),
                partition_digest: digest(&partition),
                nodes: group.len() as u64,
            });
            cohorts.push(GraphCohort {
                policy_domain: domain.clone(),
                policies,
                partition,
                graph_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            });
            for object in built.nodes {
                let node = AnnNodeV2::decode_canonical(object.value()).map_err(ann_error)?;
                nodes.push(GraphNode {
                    representation_id: node.representation_id,
                    policy_domain: domain.clone(),
                    canonical_node: object.value().to_vec(),
                    graph_digest: ContentDigest::from_bytes([0; 32]),
                    token: String::new(),
                });
            }
            members.extend(group.into_iter().map(|(m, _)| m));
        }
        members.sort_by_key(|m| m.representation_id);
        nodes.sort_by_key(|n| n.representation_id);
        Ok(GraphTopology {
            members,
            cohorts,
            nodes,
            summaries,
        })
    }
}
