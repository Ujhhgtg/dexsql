import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.maven.publish)
}

android {
    namespace = "dev.ujhhgtg.dexsql.android"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig { minSdk = libs.versions.minSdk.get().toInt() }

    compileOptions {
        sourceCompatibility = JavaVersion.toVersion(libs.versions.jdk.get())
        targetCompatibility = JavaVersion.toVersion(libs.versions.jdk.get())
    }
}

kotlin { jvmToolchain(libs.versions.jdk.get().toInt()) }

val androidAbis = mapOf("arm64-v8a" to "aarch64-linux-android", "x86_64" to "x86_64-linux-android")

val cargoBuildAndroid =
    tasks.register<CargoBuildTask>("cargoBuildAndroid") {
        configureNativeCrate(rootDir)
        targets.putAll(androidAbis)
        ndkDirectory.set(androidComponents.sdkComponents.ndkDirectory.map { it.asFile.path })
        androidApiLevel.set(libs.versions.minSdk.get().toInt())
        outputDirectory.set(layout.buildDirectory.dir("generated/cargo/jniLibs"))
    }

androidComponents.onVariants { variant ->
    variant.sources.jniLibs?.addGeneratedSourceDirectory(
        cargoBuildAndroid,
        CargoBuildTask::outputDirectory,
    )
}

dependencies { api(project(":dexsql")) }

mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            javadocJar = JavadocJar.Empty(),
            sourcesJar = SourcesJar.Sources(),
            variant = "release",
        ),
    )
    pom {
        name = "dexsql for Android"
        description = "dexsql with the Android JNI libraries (arm64-v8a, x86_64)."
    }
}
