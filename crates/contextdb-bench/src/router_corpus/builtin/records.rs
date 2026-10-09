use super::*;

pub(super) fn validate_builtin_profile(
    inputs: &[RouterQueryTimeRecord],
    targets: &[RouterUtilityTargets],
    lineage: &Lineage,
    budget: &mut QueryBudget,
) -> Result<()> {
    if lineage.nodes.len() > MAX_ROUTER_LINEAGE_NODES {
        return Err(invalid());
    }
    charge(budget, lineage.nodes.len() as u64, 0)?;
    let mut expected = BTreeMap::new();
    for group in 0..4_u32 {
        for scenario in fixture::SCENARIOS {
            let at = if matches!(
                scenario,
                fixture::Scenario::CorrectedCode | fixture::Scenario::LocalConstraint
            ) {
                4
            } else {
                3
            };
            expected.insert(
                format!("group-{group}-{scenario:?}"),
                (group, u64::from(group) * 100 + at),
            );
        }
    }
    let nodes: BTreeMap<_, _> = lineage
        .nodes
        .iter()
        .map(|node| (&node.reference, node))
        .collect();
    for (input, target) in inputs.iter().zip(targets) {
        charge(budget, 1, 0)?;
        let (group, cutoff) = expected.remove(&input.query.id).ok_or_else(invalid)?;
        let domain = format!("synthetic:router-domain:{group}");
        if input.query.logical_domain != domain
            || input.query.scope != format!("synthetic:atlas:{group}")
            || input.query.known_at != cutoff
            || input.observation.fixture_id != input.query.id
            || input.observation.compiler_domain != domain
            || input.observation.compiler_cutoff != cutoff
        {
            return Err(invalid());
        }
        let reference = RouterLineageRef {
            kind: RouterLineageKind::Evaluation,
            domain: domain.clone(),
            id: format!("source-label:{}", input.query.id),
            version: Some("v1".into()),
        };
        let evaluation = nodes.get(&reference).ok_or_else(invalid)?;
        if evaluation.available_at != cutoff + 1
            || evaluation.parents != input.observation.source_nodes
        {
            return Err(invalid());
        }
        for provenance in target
            .candidates
            .iter()
            .filter_map(|item| item.provenance.as_ref())
            .chain(
                target
                    .bundles
                    .iter()
                    .filter_map(|item| item.provenance.as_ref()),
            )
        {
            charge(budget, provenance.source_nodes.len() as u64 + 1, 0)?;
            if provenance.kind != RouterLabelKind::SyntheticSourceSet
                || provenance.evaluator_version != "synthetic-source-set.v1"
                || provenance.available_at != evaluation.available_at
                || provenance.logical_domain != domain
                || provenance.source_nodes != evaluation.parents
            {
                return Err(invalid());
            }
            for source in &provenance.source_nodes {
                if nodes
                    .get(source)
                    .is_none_or(|node| node.available_at > provenance.available_at)
                {
                    return Err(invalid());
                }
            }
        }
    }
    if !expected.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn build_artifacts(replay: bool, budget: &mut QueryBudget) -> Result<BuiltinArtifacts> {
    let mut inputs = Vec::new();
    let mut features = Vec::new();
    let mut behavior = Vec::new();
    let mut targets = Vec::new();
    let mut graph = BTreeMap::<RouterLineageRef, RouterLineageNode>::new();
    let mut examples = Vec::new();
    let mut domains = BTreeMap::new();
    for group in 0..4_u32 {
        let domain = format!("synthetic:router-domain:{group}");
        // Cutoffs are predeclared in each domain, before evaluating any target.
        domains.insert(
            domain.clone(),
            if group == 3 {
                RouterTimeCutoffs {
                    train_until: 303,
                    validation_until: 399,
                }
            } else {
                RouterTimeCutoffs {
                    train_until: 99,
                    validation_until: 199,
                }
            },
        );
        let mut parents = Vec::new();
        for kind in [
            RouterLineageKind::Workspace,
            RouterLineageKind::Project,
            RouterLineageKind::Entity,
            RouterLineageKind::Session,
            RouterLineageKind::Run,
        ] {
            let reference = RouterLineageRef {
                kind,
                domain: domain.clone(),
                id: format!("group:{group}:{kind:?}"),
                version: None,
            };
            graph.insert(
                reference.clone(),
                RouterLineageNode {
                    reference: reference.clone(),
                    available_at: u64::from(group) * 100 + 1,
                    parents: Vec::new(),
                },
            );
            parents.push(reference);
        }
        parents.sort();
        for scenario in fixture::SCENARIOS {
            let case = if replay {
                fixture::build_replay_case(group, scenario, budget)?
            } else {
                fixture::build_case(group, scenario, budget)?
            };
            case.routed
                .manifest
                .validate(
                    &case.routed.request,
                    &case.routed.plan,
                    &case.routed.assembly,
                    budget,
                )
                .map_err(|_| invalid())?;
            let mut roots = BTreeSet::new();
            for span in case
                .routed
                .prepared_material
                .evidence
                .iter()
                .filter_map(|item| item.original_span.as_ref())
                .chain(
                    case.base
                        .control
                        .iter()
                        .chain(&case.base.working)
                        .chain(&case.base.hot)
                        .chain(&case.base.current)
                        .flat_map(|message| {
                            message.originals.iter().map(|original| &original.span)
                        }),
                )
            {
                let reference = RouterLineageRef {
                    kind: RouterLineageKind::SourceVersion,
                    domain: domain.clone(),
                    id: span.event_id.to_string(),
                    version: Some(span.payload_digest.to_string()),
                };
                let (_, available_at) = case.originals.get(&span.event_id).ok_or_else(invalid)?;
                let node = RouterLineageNode {
                    reference: reference.clone(),
                    available_at: *available_at,
                    parents: parents.clone(),
                };
                if graph
                    .get(&reference)
                    .is_some_and(|previous| previous != &node)
                {
                    return Err(invalid());
                }
                graph.insert(reference.clone(), node);
                roots.insert(reference);
            }
            let roots: Vec<_> = roots.into_iter().collect();
            let observation = SyntheticObservationBinding {
                generator: fixture::GENERATOR.into(),
                fixture_id: case.fixture_id,
                source_domain: domain.clone(),
                source_cutoff: case.query.known_at,
                compiler_domain: case.routed.request.context.snapshot.database_id.clone(),
                compiler_cutoff: case.routed.request.context.snapshot.commit_seq,
                source_nodes: roots.clone(),
            };
            let observed = RouterBehaviorRecord {
                format: ROUTER_BEHAVIOR_VERSION.into(),
                example_id: case.query.id.clone(),
                request_digest: case.routed.request.digest,
                plan: case.routed.plan,
                manifest: case.routed.manifest,
                attempt: RouterAttemptStatus::Prepared,
                accepted_receipt: None,
                replay_observation: case.routed.replay_observation,
            };
            let input = RouterQueryTimeRecord {
                format: ROUTER_QUERY_VERSION.into(),
                query: case.query,
                request: case.routed.request,
                base: case.base,
                material: case.routed.prepared_material,
                observation,
            };
            let provenance = RouterLabelProvenance {
                kind: RouterLabelKind::SyntheticSourceSet,
                evaluator_version: "synthetic-source-set.v1".into(),
                available_at: input.query.known_at + 1,
                logical_domain: domain.clone(),
                source_nodes: roots.clone(),
            };
            let gold: BTreeSet<_> = case
                .evaluation
                .evidence_ids
                .iter()
                .map(|id| {
                    contextdb_context::BlockId::new(format!("raw:{id}")).map_err(|_| invalid())
                })
                .collect::<Result<_>>()?;
            let mut candidates = Vec::new();
            for unit in &input.request.units {
                let useful = if input.request.mandatory_ids.contains(&unit.id) {
                    None
                } else if matches!(scenario, fixture::Scenario::ResidentCode) {
                    Some(false)
                } else if matches!(scenario, fixture::Scenario::Complement)
                    && gold.contains(&unit.id)
                {
                    None
                } else {
                    Some(gold.contains(&unit.id))
                };
                candidates.push(CandidateUtilityTarget {
                    candidate_id: unit.id.clone(),
                    useful,
                    provenance: useful.map(|_| provenance.clone()),
                });
            }
            let bundles = if gold.len() > 1 {
                vec![BundleUtilityTarget {
                    bundle_id: "source-complement".into(),
                    members: gold.into_iter().collect(),
                    useful: Some(true),
                    provenance: Some(provenance.clone()),
                }]
            } else {
                Vec::new()
            };
            let target = RouterUtilityTargets {
                format: ROUTER_TARGET_VERSION.into(),
                example_id: input.query.id.clone(),
                conditional_base_digest: observed
                    .plan
                    .scores
                    .first()
                    .ok_or_else(invalid)?
                    .selected_base_digest,
                candidates,
                bundles,
            };
            let example = RouterExampleLineage {
                example_id: input.query.id.clone(),
                logical_domain: domain.clone(),
                cutoff: input.query.known_at,
                roots: roots.clone(),
            };
            let evaluation_ref = RouterLineageRef {
                kind: RouterLineageKind::Evaluation,
                domain: domain.clone(),
                id: format!("source-label:{}", input.query.id),
                version: Some("v1".into()),
            };
            graph.insert(
                evaluation_ref.clone(),
                RouterLineageNode {
                    reference: evaluation_ref,
                    available_at: provenance.available_at,
                    parents: roots,
                },
            );
            validate_router_example(&input, &observed, &target, &example, budget)?;
            features.push(build_router_features(&input, budget)?);
            inputs.push(input);
            behavior.push(observed);
            targets.push(target);
            examples.push(example);
        }
    }
    let nodes: Vec<_> = graph.into_values().collect();
    let split = RouterSplitSpec { domains };
    let assignments = assign_router_group_time_split(&nodes, &examples, &split, budget)?;
    let lineage = Lineage {
        nodes,
        examples,
        split,
        assignments,
    };
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    files.insert(
        FILES[0].into(),
        router_corpus_bytes(&inputs, MAX_ROUTER_EXAMPLE_BYTES, budget)?,
    );
    files.insert(
        FILES[1].into(),
        router_corpus_bytes(&features, MAX_ROUTER_EXAMPLE_BYTES, budget)?,
    );
    files.insert(
        FILES[2].into(),
        router_corpus_bytes(&behavior, MAX_ROUTER_EXAMPLE_BYTES, budget)?,
    );
    files.insert(
        FILES[3].into(),
        router_corpus_bytes(&targets, MAX_ROUTER_EXAMPLE_BYTES, budget)?,
    );
    files.insert(
        FILES[4].into(),
        router_corpus_bytes(&lineage, MAX_ROUTER_EXAMPLE_BYTES, budget)?,
    );
    let artifacts = files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                Artifact {
                    bytes: bytes.len() as u64,
                    digest: ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
                },
            )
        })
        .collect();
    let manifest = Manifest {
        format: if replay {
            REPLAY_FORMAT
        } else {
            ROUTER_CORPUS_VERSION
        }
        .into(),
        builder: if replay { REPLAY_BUILDER } else { BUILDER }.into(),
        generator: fixture::GENERATOR.into(),
        examples: inputs.len(),
        artifacts,
    };
    Ok(BuiltinArtifacts { manifest, files })
}
