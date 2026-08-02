plugins {
    id("com.android.application")
}

android {
    namespace = "io.apkscanner.probe"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.apkscanner.probe"
        // The receiver requires android.permission.DUMP, held by adb shell but not ordinary apps.
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}
