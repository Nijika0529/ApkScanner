# Version security evolution

ApkScanner treats a new APK version as a new security claim. Historical results
accelerate validation, but never become current-version Findings without new
evidence.

## Security snapshot and semantic Diff

After static inspection, the platform stores a content-addressed snapshot of:

- package, signer, and version identity;
- externally reachable entries and manifest protections;
- normalized component code hashes;
- security-relevant API calls, caller guards, and sensitive sinks.

The automatic baseline is the latest earlier scan with the same package name and
the same signing certificate. Diff maps exact entry identities first and uses
normalized code only to recognize an unambiguous rename. It reports exposure,
permission, guard, implementation, entry-addition, and entry-removal changes.

## Proven PoC migration and replay

Only `reproduced_blackbox` or manually `accepted` Findings can seed replay. The
source archive from the original platform-built PoC is hash-verified and safely
extracted into the target task workspace. Deterministic component and authority
renames are substituted, then the PoC is rebuilt and signed by the current
toolchain.

Replay runs while the target task owns the device. Its result is a new
`ProofAttempt` evaluated by the current-version Oracle. A successful replay may
produce a current Finding; a miss or build failure is passed to the Agent as
evidence for adaptation. The old Finding itself is never copied.

## Finding pattern cards

A reusable pattern is created only from a dynamically proven or accepted
Finding. It contains a package-independent vulnerability class, entry shape,
security API signature, absent guards, exclusions, and a proof recipe.

Pattern search produces `candidate_match` records and raises the priority of the
matching queued task. Matches never appear as confirmed Findings until a new
platform proof demonstrates harm.

## API

- `GET /api/v1/scans/{scan_id}/security-snapshot`
- `GET /api/v1/scans/{scan_id}/version-diff`
- `GET /api/v1/scans/{scan_id}/pattern-matches`
- `GET /api/v1/patterns`
- `GET /api/v1/patterns/{pattern_id}`

The console displays these records under **版本演进**.
