//! Learned-only typed data; opaque native locators remain in owner custody.

use super::*;
use contextdb_core::ClaimObject;

const MAX_TEXT: usize = 16_384;

fn unsupported() -> ServiceError {
    super::super::unsupported("native material has no supported natural learned projection")
}

fn text(value: &str, budget: &mut QueryBudget) -> ServiceResult<()> {
    budget.charge(1, value.len() as u64).map_err(budget_error)?;
    if value.len() > MAX_TEXT {
        return Err(unsupported());
    }
    Ok(())
}

fn literal(value: &ClaimObject, budget: &mut QueryBudget) -> ServiceResult<String> {
    use ClaimObject::*;
    let length = match value {
        String(value) | Uri(value) => value.len(),
        Quantity { unit, .. } => unit.len().saturating_add(64),
        Integer(_) | Float(_) | Boolean(_) | Timestamp(_) | TimeRange(_) => 128,
        Node(_) | CodeLocation { .. } | Structured(_) => return Err(unsupported()),
    };
    if length > MAX_TEXT {
        return Err(unsupported());
    }
    budget.charge(1, length as u64).map_err(budget_error)?;
    let rendered = match value {
        String(value) | Uri(value) => value.clone(),
        Integer(value) => value.to_string(),
        Float(value) if value.is_finite() => value.to_string(),
        Boolean(value) => value.to_string(),
        Timestamp(value) => format!("Timestamp in microseconds: {}", value.0),
        TimeRange(value) => format!(
            "Time interval in microseconds: {} to {}",
            value.start.0,
            value
                .end
                .map_or_else(|| "open".into(), |end| end.0.to_string())
        ),
        Quantity { value, unit } if value.is_finite() => format!("{value} {unit}"),
        _ => return Err(unsupported()),
    };
    Ok(rendered)
}

pub(super) fn state(
    candidate: &mut PackCandidate,
    resolution: &ResolvedState,
    usable: bool,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    // Caller already resolved current authority/use and attached exact support.
    // Never render a withheld value just because it exists in the native view.
    candidate.facets.clear();
    candidate.representations[0].fields.clear();
    if !usable {
        return Ok(());
    }
    match resolution {
        ResolvedState::Known { answer } => {
            candidate.exact_fragments.push(ExactFragment {
                label: "Resolved value".into(),
                value: literal(&answer.value, budget)?,
            });
        }
        ResolvedState::Conflict { alternatives } => {
            if alternatives.len() > 64 {
                return Err(unsupported());
            }
            for (index, alternative) in alternatives.iter().enumerate() {
                candidate.exact_fragments.push(ExactFragment {
                    label: format!("Conflicting value {}", index + 1),
                    value: literal(&alternative.value, budget)?,
                });
            }
        }
        ResolvedState::Unknown | ResolvedState::Incomplete => {}
    }
    Ok(())
}

pub(super) fn validate_candidates(
    candidates: &[ProviderCandidate],
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    for item in candidates {
        let candidate = &item.candidate;
        if !candidate.facets.is_empty() {
            return Err(unsupported());
        }
        for representation in &candidate.representations {
            if !representation.omitted_facets.is_empty() {
                return Err(unsupported());
            }
            if candidate.kind != PackBlockKind::RawObservation {
                text(&representation.summary, budget)?;
                for (name, value) in &representation.fields {
                    if !matches!(name.as_str(), "reason" | "question" | "missing_facet") {
                        return Err(unsupported());
                    }
                    text(value, budget)?;
                }
            }
        }
        for fragment in &candidate.exact_fragments {
            text(&fragment.label, budget)?;
            text(&fragment.value, budget)?;
        }
    }
    Ok(())
}

pub(super) fn validate_unit(
    unit: &SemanticScoringUnit<'_>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    for message in unit
        .base
        .control
        .iter()
        .chain(&unit.base.working)
        .chain(&unit.base.hot)
        .chain(&unit.base.current)
    {
        text(&message.text, budget)?;
    }
    for view in [unit.selected, unit.trial] {
        for block in view.pack.sections.iter() {
            if !block.facets.is_empty() || !block.representation.omitted_facets.is_empty() {
                return Err(unsupported());
            }
            if block.kind != PackBlockKind::RawObservation {
                text(&block.representation.summary, budget)?;
                for (name, value) in &block.representation.fields {
                    if !matches!(name.as_str(), "reason" | "question" | "missing_facet") {
                        return Err(unsupported());
                    }
                    text(value, budget)?;
                }
            }
            for fragment in &block.exact_fragments {
                text(&fragment.label, budget)?;
                text(&fragment.value, budget)?;
            }
            if let Some(unknown) = &block.unknown {
                text(&unknown.question, budget)?;
                text(&unknown.reason, budget)?;
            }
        }
        for evidence in &view.pack.evidence {
            if let Some(excerpt) = &evidence.excerpt {
                text(excerpt, budget)?;
            }
        }
        for message in view.messages {
            for original in &message.originals {
                let bytes = original
                    .text_end
                    .checked_sub(original.text_start)
                    .ok_or_else(unsupported)?;
                if bytes > MAX_TEXT as u64 {
                    return Err(unsupported());
                }
            }
        }
    }
    Ok(())
}
