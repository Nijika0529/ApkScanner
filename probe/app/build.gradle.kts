plugins {
    id("com.android.application")
}

android {
    namespace = "io.apkscanner.probe"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.apkscanner.probe"
        // Probe identity validation uses BroadcastReceiver.getSentFromUid().
        minSdk = 36
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}
