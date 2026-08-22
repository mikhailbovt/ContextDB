# Portable example database

This example is a canonical `contextdb.logical.v1` archive containing one
private, consented observation about the historical Japan-bar discussion. It is
small enough for install and migration smoke tests and intentionally contains no
real personal data, provider output, embedding, or model credential.

Files:

- `source/observe-japan-bar.json` is the reproducible canonical observation.
- `payload/japan-bar.ctxb` is the logical archive exported by the current
  `contextdb` CLI.
- `payload/example.json` records non-secret fixture metadata and the expected
  deep-verify head.
- `contextdb-portable-example.zip` is a deterministic ZIP of `payload`.
- `package-receipt.json` records ZIP members and SHA-256 values. It is packaging
  evidence only and explicitly not a release receipt.

The standalone packager requires exactly one `.ctxb`, rejects conventional key
material (`.key`, `.pem`, `.p12`, `.pfx`), rejects links and unsafe paths, and
applies the same bounded entry/expanded-size limits as clean-install extraction.

No key or `.ctxb.key` is distributed. Import requires an independently supplied
external key; its file must be outside the archive directory:

```text
on Windows set CONTEXTDB_TOKEN_KEY_HEX from an OS secret store and set a fresh CONTEXTDB_STATE_HEAD_ID
on Unix set exactly one token-key source and a fresh owner-only external CONTEXTDB_STATE_HEAD_FILE
contextdb --json import imported.ctxb payload/japan-bar.ctxb
contextdb --json doctor imported.ctxb
```

For the token key, set exactly one of `CONTEXTDB_TOKEN_KEY_HEX` and
`CONTEXTDB_TOKEN_KEY_FILE`. The file form is Unix-only: it is an absolute
external regular file containing exactly 64 hexadecimal characters plus an
optional single line ending, with one hard link, owner identity matching the
process, and no group/other permission bits. Windows intentionally rejects the
file form. The state-head selector is an additional, independent requirement,
not a second token-key source. Neither it nor the token key may be packaged or
placed beside `imported.ctxb`.

Import is clone-only: the destination archive and selected authority must both
be fresh, and `--force` is disabled. Key/state-head custody, backup, rotation or
lifecycle, and custodian rollback protection must still close before release
proof.

The archive is portable at the logical format boundary, not a byte-for-byte
copy of a production database. The final release still requires import/doctor
receipts on each supported platform and version-compatibility evidence.
