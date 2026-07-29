# APKScanner local test APKs

`vulntest.apk` is a deliberately vulnerable, minimal Android application for
end-to-end scanner testing. Its reproducible source is in `vulntest-src/` and
its expected vulnerability catalogue is in `vulntest-ground-truth.json`.

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
```

The checked-in keystore is a public, test-only key used solely to make fixture
builds stable. Never use it to sign a real application.
