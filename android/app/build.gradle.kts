import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The package name other apps would see. Override for your own build, so
// that no list of "known VPN apps" contains it:
//   ./gradlew assembleRelease -PappId=com.example.notes
val appId = (project.findProperty("appId") as String?) ?: "net.nevio.app"
val appVersion = (project.findProperty("appVersion") as String?) ?: "0.0.0-dev"
// The name shown under the icon, in Settings → Apps and in the VPN dialog.
val appName = (project.findProperty("appName") as String?) ?: "nevio"

// Release signing: keystore.properties in android/, or the NEVIO_KEYSTORE*
// environment variables (CI). Without them the release APK is signed with
// the debug key of the build machine.
val keyProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun keyProp(name: String, env: String): String? = keyProps.getProperty(name) ?: System.getenv(env)

android {
    namespace = "net.nevio.app"
    compileSdk = 35

    defaultConfig {
        applicationId = appId
        minSdk = 26
        targetSdk = 35
        // 1.2.3 → 10203
        versionCode = appVersion.trimStart('v').split('.', '-').take(3)
            .map { it.toIntOrNull() ?: 0 }.let { (it + listOf(0, 0, 0)).take(3) }
            .let { (a, b, c) -> a * 10000 + b * 100 + c }.coerceAtLeast(1)
        versionName = appVersion
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        resValue("string", "app_name", appName)
    }

    signingConfigs {
        val store = keyProp("storeFile", "NEVIO_KEYSTORE")
        if (store != null) {
            create("release") {
                storeFile = file(store)
                storePassword = keyProp("storePassword", "NEVIO_KEYSTORE_PASSWORD")
                keyAlias = keyProp("keyAlias", "NEVIO_KEY_ALIAS")
                keyPassword = keyProp("keyPassword", "NEVIO_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Without a private key: the debug key of the machine that builds
            // (see signing/README.md).
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = true } }
}

dependencies {
    // The Go core (gomobile bind ./mobile), built by "make android-aar".
    implementation(files("libs/nevio.aar"))
}
