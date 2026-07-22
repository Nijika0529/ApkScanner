# APK Scanner Probe

This deliberately exported helper performs one cross-application call from an ordinary Android
application UID. It is evidence infrastructure, not a production application.

Build with Android Studio or a system Gradle installation and an Android SDK containing API 36:

```bash
gradle :app:assembleDebug
```

Then point the scanner at `app/build/outputs/apk/debug/app-debug.apk` with
`APKSCANNER_PROBE_APK`. Never install the probe on employee or production devices.
