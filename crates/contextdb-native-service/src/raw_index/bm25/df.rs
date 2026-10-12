//! Sparse DF absence cannot overwrite a previously eligible occurrence.

use super::*;

const MAX_ABSENCE_ROWS: usize = 256;

impl NativeService {
    #[allow(
        clippy::too_many_arguments,
        reason = "absence is checked against the same staged source/domain transaction"
    )]
    pub(super) fn require_absent_bm25_df<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        document: &Bm25Document,
        term: &str,
        staged: &BTreeMap<Vec<u8>, Vec<u8>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let prefix = format!(
            "{}route/{}/term/{}/",
            generation_prefix(workspace, generation),
            document.policy_domain,
            digest_bytes(term.as_bytes())
        )
        .into_bytes();
        budget
            .charge(1, (prefix.len() * 2) as u64)
            .map_err(budget_error)?;
        let mut inspected = 0;
        for (key, value) in staged
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
        {
            self.check_bm25_df_absence_row(
                snapshot, workspace, generation, document, term, &prefix, key, value, staged,
                budget,
            )?;
            inspected += 1;
            if inspected > MAX_ABSENCE_ROWS {
                return Err(exhausted(
                    "BM25 sparse frequency absence exceeds its bounded proof",
                ));
            }
        }
        let mut after = None;
        loop {
            budget
                .charge(1, prefix.len() as u64 + 64)
                .map_err(budget_error)?;
            let max_bytes = (budget.remaining_bytes() / 2).min(64 * 1024) as usize;
            if max_bytes == 0 {
                return Err(budget_error(QueryLimit::Bytes));
            }
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: after.as_deref(),
                        max_entries: 1,
                        max_bytes,
                    },
                )
                .map_err(storage_error)?;
            let Some(entry) = page.entries.first() else {
                return Ok(());
            };
            budget
                .charge(1, ((entry.key.len() + entry.value.len()) * 2) as u64)
                .map_err(budget_error)?;
            self.check_bm25_df_absence_row(
                snapshot,
                workspace,
                generation,
                document,
                term,
                &prefix,
                &entry.key,
                &entry.value,
                staged,
                budget,
            )?;
            inspected += 1;
            if inspected > MAX_ABSENCE_ROWS {
                return Err(exhausted(
                    "BM25 sparse frequency absence exceeds its bounded proof",
                ));
            }
            if page.continuation.is_none() {
                return Ok(());
            }
            after = Some(entry.key.clone());
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the posting and statistical source must agree before sparse initialization"
    )]
    fn check_bm25_df_absence_row<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        document: &Bm25Document,
        term: &str,
        prefix: &[u8],
        key: &[u8],
        value: &[u8],
        staged: &BTreeMap<Vec<u8>, Vec<u8>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget
            .charge(1, (key.len() + value.len()) as u64)
            .map_err(budget_error)?;
        let id: ObservationId = decode(value, "BM25 sparse frequency posting")?;
        let previous: Bm25Document = staged_value(
            self,
            snapshot,
            staged,
            &document_key(workspace, generation, id),
            budget,
        )?
        .ok_or_else(|| integrity("BM25 prior posting lost its statistical source"))?;
        previous.validate()?;
        let expected = [prefix, format!("{:020}/{id}", previous.commit).as_bytes()].concat();
        if key != expected
            || previous.source.event_id != id
            || previous.policy_domain != document.policy_domain
            || previous.commit >= document.commit
        {
            return Err(integrity(
                "BM25 prior posting differs from its statistical source",
            ));
        }
        if previous.term_frequencies.contains_key(term) {
            return Err(integrity(
                "BM25 required previous document frequency is absent",
            ));
        }
        Ok(())
    }
}
