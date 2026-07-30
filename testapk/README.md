# APKScanner local test APKs

`vulntest.apk` is a deliberately vulnerable, minimal Android application for
end-to-end scanner testing. Its reproducible source is in `vulntest-src/` and
its expected vulnerability catalogue is in `vulntest-ground-truth.json`.

`rescuetest.apk` is a one-seed fixture for the blind negative-closure rescue
gate. Its exported `EntryActivity` looks shallow, but delegates an attacker
`PendingIntent` through `TelemetryRoute` to the non-exported `VaultRelay`,
which returns a secret to the ordinary third-party caller.

`specialcases.apk` is a static-semantic fixture modeled after a large
privileged assistant application. It covers an exported Binder service that
trusts caller-supplied identity, a shell-policy/real-shell mismatch, an
internal WebView with a sensitive JavaScript bridge, a pre-production endpoint,
an embedded service secret, a persistent unauthenticated policy update,
an unbound authorization callback, and external session switching.

Covered paths:

- exported `MainActivity` with `target_activity` → `Class.forName` →
  `startActivity`;
- attacker-supplied `inner_intent` → `startActivity`;
- URL-decoding WebView path with JavaScript and `VulnBridge.getSecret`;
- exported deep link `vulntest://open?url=...`;
- exported permissionless credential `ContentProvider`;
- exported permissionless Binder `Service`;
- exported `BroadcastReceiver` that starts a non-exported sensitive Activity;
- signature-permission-protected `SafeActivity` as a negative control.

Build from the repository root:

```bash
testapk/build-vulntest.sh
testapk/build-rescuetest.sh
testapk/build-specialcases.sh
```

The checked-in keystore is a public, test-only key used solely to make fixture
builds stable. Never use it to sign a real application.
