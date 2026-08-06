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

`adaptivecases.apk` is the Android attack-chain and terminal Adaptive Verifier
fixture. It targets API 36 while retaining minSdk 26. Its five positive cases
cover ACTION_SEND Zip Slip import, an exported dynamic receiver, an
unauthenticated localhost server, a WebView JS bridge credential leak, and a
multi-value Binder credential reply. It also contains two adversarial controls:
a mutable implicit PendingIntent whose redirected receiver sees the URI but does
not receive permission to open the private provider, and a signature-protected
immutable PendingIntent activity. The first control is intentionally close to a
real capability-delegation bug so the scanner must not equate redirection with a
demonstrated URI disclosure.

`copilotfixture.apk` is a product-bundle fixture for the Copilot-focused asset
pipeline. It targets API 36, embeds a separately signed `entityplugin.apk`, loads
its concrete `EntityPluginEntrance` through `DexClassLoader`, calls an ARM64 JNI
library, and includes an exported WebView/JSBridge route plus a duplicate activity
alias. A successful device launch logs `PLUGIN_OK NATIVE_OK=42`; this proves that
the same host → embedded APK → plugin entry and Java → JNI → SO paths represented
by ArtifactGraph are executable on a real device.
The adaptive fixture build normalizes ZIP timestamps and disables v1 signing so
repeated builds from unchanged sources produce the same APK SHA-256.

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
testapk/build-adaptivecases.sh
testapk/build-copilotfixture.sh
```

The checked-in keystore is a public, test-only key used solely to make fixture
builds stable. Never use it to sign a real application.
