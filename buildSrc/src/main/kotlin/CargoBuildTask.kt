import java.io.File
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileSystemOperations
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations

/**
 * Builds the `native/` cdylib with Cargo for one or more Rust targets and lays the results out as
 * `<outputDir>/<subdirectory>/lib<name>.so`.
 *
 * The Android toolchain is passed to Cargo only through environment variables
 * (`CARGO_TARGET_<TRIPLE>_LINKER`, `CC_<triple>`, `CXX_<triple>`, `AR_<triple>`) derived from
 * [ndkDirectory]; no `.cargo/config.toml` is read or written. Variables already present in the
 * environment win, so CI or developers can point any target at a different linker.
 */
abstract class CargoBuildTask
@Inject
constructor(
    private val exec: ExecOperations,
    private val files: FileSystemOperations,
) : DefaultTask() {
    /** Crate sources, manifest, lockfile and toolchain file (for up-to-date checks). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val crateSources: ConfigurableFileCollection

    @get:Internal abstract val crateDirectory: DirectoryProperty

    /** Shared Cargo target directory; Cargo's own lock serializes concurrent builds. */
    @get:Internal abstract val cargoTargetDirectory: DirectoryProperty

    /** Output subdirectory (an Android ABI or a resource path) to Rust target triple. */
    @get:Input abstract val targets: MapProperty<String, String>

    @get:Input abstract val libraryName: Property<String>

    /** Cargo executable; defaults to `cargo` on PATH. */
    @get:Input abstract val cargo: Property<String>

    /** Optional rustup toolchain override (`RUSTUP_TOOLCHAIN`); otherwise rust-toolchain.toml. */
    @get:Input @get:Optional abstract val rustToolchain: Property<String>

    /** NDK root; required only for `*-android*` targets. */
    @get:Input @get:Optional abstract val ndkDirectory: Property<String>

    @get:Input abstract val androidApiLevel: Property<Int>

    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun build() {
        val crate = crateDirectory.get().asFile
        val targetDir = cargoTargetDirectory.get().asFile
        val output = outputDirectory.get().asFile
        files.delete { delete(output) }
        for ((subdirectory, triple) in targets.get()) {
            val toolchainEnvironment = linkerEnvironment(triple)
            exec.exec {
                workingDir = crate
                executable = cargo.get()
                args(
                    "build",
                    "--release",
                    "--locked",
                    "--manifest-path",
                    crate.resolve("Cargo.toml").path,
                    "--target",
                    triple,
                )
                environment("CARGO_TARGET_DIR", targetDir.path)
                rustToolchain.orNull?.let { environment("RUSTUP_TOOLCHAIN", it) }
                toolchainEnvironment.forEach { (key, value) -> environment(key, value) }
            }
            val fileName = libraryFileName(triple)
            val artifact = targetDir.resolve("$triple/release/$fileName")
            if (!artifact.isFile) {
                throw GradleException("cargo did not produce $artifact")
            }
            artifact.copyTo(output.resolve("$subdirectory/$fileName"), overwrite = true)
        }
    }

    private fun linkerEnvironment(triple: String): Map<String, String> {
        if (!triple.contains("-android")) return emptyMap()
        val ndk =
            ndkDirectory.orNull?.let(::File)
                ?: throw GradleException("Android NDK is required to build $triple")
        val bin = ndk.resolve("toolchains/llvm/prebuilt/${ndkHostTag()}/bin")
        val suffix = if (isWindows()) ".cmd" else ""
        val exe = if (isWindows()) ".exe" else ""
        val clang = bin.resolve("${clangPrefix(triple)}${androidApiLevel.get()}-clang$suffix")
        val clangxx = bin.resolve("${clangPrefix(triple)}${androidApiLevel.get()}-clang++$suffix")
        val ar = bin.resolve("llvm-ar$exe")
        if (!clang.isFile) throw GradleException("NDK clang not found: $clang")
        val cargoKey = triple.uppercase().replace('-', '_')
        val ccKey = triple.replace('-', '_')
        return mapOf(
                "CARGO_TARGET_${cargoKey}_LINKER" to clang.path,
                "CARGO_TARGET_${cargoKey}_AR" to ar.path,
                "CC_$ccKey" to clang.path,
                "CXX_$ccKey" to clangxx.path,
                "AR_$ccKey" to ar.path,
            )
            .filterKeys { System.getenv(it) == null }
    }

    private fun clangPrefix(triple: String): String =
        when (triple) {
            "armv7-linux-androideabi" -> "armv7a-linux-androideabi"
            else -> triple
        }

    private fun libraryFileName(triple: String): String {
        val name = libraryName.get()
        return when {
            triple.contains("windows") -> "$name.dll"
            triple.contains("apple") -> "lib$name.dylib"
            else -> "lib$name.so"
        }
    }

    private fun isWindows() = System.getProperty("os.name").orEmpty().startsWith("Windows")

    private fun ndkHostTag(): String {
        val os = System.getProperty("os.name").orEmpty()
        return when {
            os.startsWith("Linux") -> "linux-x86_64"
            os.startsWith("Mac") -> "darwin-x86_64"
            os.startsWith("Windows") -> "windows-x86_64"
            else -> throw GradleException("unsupported NDK host: $os")
        }
    }
}

/** Shared wiring for tasks that build the repository's `native/` crate. */
fun CargoBuildTask.configureNativeCrate(rootDirectory: File) {
    val crate = rootDirectory.resolve("native")
    crateDirectory.set(crate)
    crateSources.from(
        crate.resolve("src"),
        crate.resolve("Cargo.toml"),
        crate.resolve("Cargo.lock"),
        crate.resolve("rust-toolchain.toml"),
    )
    cargoTargetDirectory.set(crate.resolve("target"))
    libraryName.set("dexsql_jni")
    cargo.convention(
        project.providers
            .gradleProperty("dexsql.cargo")
            .orElse(project.providers.environmentVariable("CARGO"))
            .orElse("cargo"),
    )
    rustToolchain.set(project.providers.gradleProperty("dexsql.rustToolchain"))
    androidApiLevel.convention(21)
}
