# APK Scanner Probe

This deliberately exported helper performs one cross-application call from an ordinary Android
application UID. Its exported receiver requires `android.permission.DUMP`, so only the ADB shell or
another platform-trusted caller can submit requests. It is evidence infrastructure, not a
production application.

In addition to Activity, Receiver, Provider, and Service-start probes, version 0.3 supports a
bounded Service `binder_transact` operation. The Probe performs the bind and Parcel read itself and
emits a request-ID-correlated structured result; an Agent-authored APK or log claim is not trusted
for the returned value.

The reproducible project build uses the pinned worker image and the repository's test-only signing
key, without requiring a host Gradle or Android SDK installation:

```bash
./probe/build-probe.sh
```

Alternatively, build with Android Studio or a system Gradle installation and an Android SDK
containing API 36:

```bash
gradle :app:assembleDebug
```

Then point the scanner at `app/build/outputs/apk/debug/app-debug.apk` with
`APKSCANNER_PROBE_APK`. Never install the probe on employee or production devices.
