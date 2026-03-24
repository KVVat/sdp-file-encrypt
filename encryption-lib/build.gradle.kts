import java.text.SimpleDateFormat
import java.util.Date

plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.android.niapsec.encryption"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures.buildConfig = true

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    defaultConfig {
        val dateFormat = SimpleDateFormat("yyMMdd")
        val buildTime = dateFormat.format(Date())
        buildConfigField("String", "BUILD_DATE", "\"${buildTime}\"")
    }
}

configurations.all {
    resolutionStrategy {
        force("com.google.crypto.tink:tink-android:1.20.0")
        force("com.google.crypto.tink:tink-core:1.20.0")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation("com.google.crypto.tink:tink-android:1.20.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
