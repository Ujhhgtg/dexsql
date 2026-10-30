import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.maven.publish)
}

kotlin { jvmToolchain(libs.versions.jdk.get().toInt()) }

dependencies {
    api(libs.kotlinx.serialization.json)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    // Integration tests load the host JNI library through the bundled-natives path.
    testRuntimeOnly(project(":dexsql-natives-linux-x86_64"))
}

tasks.test {
    useJUnitPlatform()
    systemProperty("dexsql.fixtures", rootProject.file("fixtures/dex").absolutePath)
}

mavenPublishing {
    configure(KotlinJvm(javadocJar = JavadocJar.Empty(), sourcesJar = SourcesJar.Sources()))
    pom {
        name = "dexsql"
        description =
            "Kotlin/JVM bindings, query matcher and SQL DSL for the dexsql DEX/APK query engine."
    }
}
