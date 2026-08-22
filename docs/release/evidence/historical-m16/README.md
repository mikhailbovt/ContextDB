# Historical M16 observations

These files are preserved from their former `proof/M16/` locations with only
the command-path normalization documented below. They originated in commit
`15fc770609e7301cf8e05c2115a99e4459e888e1` (`Build ContextDB v1 foundation
through M17 hardening`).

They are historical package observations, not canonical proof for the current
M16 contracts. Their document shapes predate the exact schemas now declared by
`docs/roadmap/gates.json`, they are not bound to the current source snapshot,
and they must not be used to mark M16 or a formal release as passed.

The canonical `proof/M16/` paths therefore remain absent while M16 is
`not_started`. A future M16 run must generate fresh, schema-valid receipts at
those paths from one frozen source inventory.

The only post-move normalization removed the local account's Cargo-bin path
from the two recorded fuzz command strings; it does not change the recorded
test outcome. Current SHA-256 values:

| File | SHA-256 |
|---|---|
| `BENCH-G.json` | `c59fd5f66b4a8cf142aa3d633bbb89e0b17796f7245865e51a14efc370277fc9` |
| `fault-delete-restore.json` | `e007bfaa25c8024505c93bc407e57847aa8ecd94c9949d082c93f40379132e07` |
| `fuzz-smoke.json` | `89fac86306df6a43ed82e1ca8c2c5df4a095b18bd633fa090e083f7e7e912742` |
| `process-kill-redb.json` | `e3cc92bb4dcf8dec3d1eb4569340b7e7a3148ebf788808e65bab562b7cab1016` |
| `sbom-index.json` | `b026104dc719faec432b8762b7a9c52659806808ca4af95d9905a01702c76ffd` |
