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
        versionCode = 2
        versionName = "0.2.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}
