import com.vanniktech.maven.publish.JavaLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar

plugins {
    `java-library`
    alias(libs.plugins.maven.publish)
}

// Host build of the JNI library, packaged at the classpath location DexSqlLibrary probes.
// Resource-only jar; advertise the same JVM as :dexsql.
java { toolchain { languageVersion = JavaLanguageVersion.of(libs.versions.jdk.get().toInt()) } }

val cargoBuildHost =
    tasks.register<CargoBuildTask>("cargoBuildHost") {
        configureNativeCrate(rootDir)
        targets.put("dev/ujhhgtg/dexsql/native/linux-x86_64", "x86_64-unknown-linux-gnu")
        outputDirectory.set(layout.buildDirectory.dir("generated/cargo"))
    }

sourceSets.main { resources.srcDir(cargoBuildHost) }

mavenPublishing {
    configure(JavaLibrary(javadocJar = JavadocJar.Empty(), sourcesJar = SourcesJar.Empty()))
    pom {
        name = "dexsql natives (Linux x86_64)"
        description =
            "Desktop Linux x86_64 build of the dexsql JNI library, loaded by dev.ujhhgtg:dexsql."
    }
}
