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
Its `BridgeActivity` logs a target-UID `onPageFinished` URL as a fixture-specific
main-frame observation; this is not a system-level WebView callback or iframe
origin proof. The bridge exposes both a token-return method and a void
`setTransferEnabled` method whose effect appears as `transfer:on` in target UI.
`SafeBridgeActivity` loads the same external page without adding a JavaScript
bridge, providing a paired negative control. The platform Web observer can serve
top-level, redirected, and iframe pages against these entries; a callback alone
is deliberately insufficient to prove a token leak or state change.
`webobserverattacker.apk` is a separate ordinary-UID sender for these Deep Links;
it is not part of the target APK. The smoke runner uses the platform observer's
one-time experiment and phase nonces and runs browser/no-bridge controls. The
default fixture token is a fixed teaching value, so the default smoke run
validates the proof pipeline, not a real account credential leak.
For a stronger controlled-effect run, `--case bridge-top --controlled-canary`
creates a task-bound canary fixture. The platform verifies that the installed
target APK bytes match the scan, then asks the target Provider to generate its
own unpredictable value. The Provider returns only a SHA-256 digest and a
target-side count/URL digest of `getSessionToken` calls; the platform compares
those with the Web callback after ordinary-UID execution. The Provider requires
both `DUMP` and Android shell caller UID, because `DUMP` can be ADB-granted to
an ordinary app. The target value itself is never returned over ADB.
The ordinary-UID attacker APK has a `FixturePermissionProbeActivity` for a
negative check: it should log `fixture_permission_probe=oracle_permission_denied`
even when ADB has granted that app `DUMP`. This canary is synthetic and only
validates the controlled fixture's evidence chain; it is not a real session
credential or a general Oracle for arbitrary target APKs. The `pm path`
state check used by the smoke run proves installation only, not login.
Until Web callback retention and API access controls are hardened, run these
experiments only with synthetic data, never real account credentials. A
read-only Judge should reject promotion whenever a callback is only
client-reported or independent victim state and harm evidence are absent; that
is the intended Oracle-gap behavior, not a failing negative control.

`bridgefocus.apk` is a one-vulnerability Android 16 regression fixture for the
ordinary-UID UI state proof path. Its only exported component,
`BridgeActivity`, accepts `bridgefocus://web?url=...`, loads the supplied URL in
a JavaScript-enabled WebView, and exposes `StateBridge.setEnabled(boolean)`.
An attacker page that calls `StateBridge.setEnabled(true)` persistently changes
the target's configuration and native TextView from `state:off` to `state:on`.
On a later launch, the native TextView is initialized from that saved state,
not a hard-coded `state:off` label.
The benchmark truth requires an
ordinary-app execution and a platform-observed `ui_text` transition with
`unauthorized_state_change`; a page log or a successful void return alone does
not satisfy it. The fixture is deliberately limited to one dynamic positive
case and has no negative controls. Its SHA-256 is pinned in
`bridgefocus-ground-truth.json`, and its source is in `bridgefocus-src/`.

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
testapk/build-bridgefocus.sh
testapk/build-webobserverattacker.sh
testapk/build-copilotfixture.sh
```

`build-adaptivecases.sh` uses the installed Android 36 SDK and Java 17 when
available, falling back to the worker image otherwise.
With a connected test device, run `python testapk/run-web-observer-smoke.py
--serial <adb-serial> --case bridge-top` (also `safe-no-bridge`,
`bridge-iframe`, or `bridge-redirect`). Add `--retain-artifacts` to keep the
temporary SQLite database and stored evidence for read-only review.
Use `--case bridge-top --controlled-canary` to require the independent
`web.experiment.target_effect` receipt; this mode intentionally runs only the
top-level case. A callback or a successful shell command by itself does not
mark a finding reproduced: semantic Judge and the platform policy gate must
still accept the frozen evidence.
For an operator-configured HTTPS observer, add `--remote-observer`; this is
disabled by default. The dedicated SSH config, alias, HTTPS origin, and remote
loopback port must be supplied with the corresponding `--remote-*` options.
Transport health, ordinary-UID launch, target page completion, callback and
browser controls remain separate receipts; a successful smoke run does not
create a formal Finding or replace the read-only Judge and policy gate.

The checked-in keystore is a public, test-only key used solely to make fixture
builds stable. Never use it to sign a real application.
