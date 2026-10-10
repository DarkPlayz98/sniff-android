plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val appVersion = (project.findProperty("appVersion") as String?) ?: "0.4.0"
val parts = appVersion.split(".").map { it.toIntOrNull() ?: 0 } + listOf(0, 0, 0)
val appVersionCode = parts[0] * 10000 + parts[1] * 100 + parts[2]

android {
    namespace = "com.sniff.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.sniff.app"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersion
    }

    signingConfigs {
        create("release") {
            // MVP ONLY: committed keystore + password from env. Move to repo secrets before any Play Store upload.
            storeFile = rootProject.file("keystore/sniff-release.jks")
            storeType = "pkcs12"
            storePassword = System.getenv("SNIFF_KEYSTORE_PASSWORD") ?: "sniff-mvp-2026"
            keyAlias = "sniff"
            keyPassword = System.getenv("SNIFF_KEYSTORE_PASSWORD") ?: "sniff-mvp-2026"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}
