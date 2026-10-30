package dev.ujhhgtg.dexsql

import java.io.File
import java.io.InputStream
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.createTempDirectory
import kotlin.io.path.div
import kotlin.io.path.outputStream

/**
 * Locates and loads `libdexsql_jni` once per class loader.
 *
 * Resolution order on first use of the native API:
 * 1. a library explicitly passed to [load];
 * 2. the `dexsql.library.path` system property (absolute path to the shared library);
 * 3. a bundled desktop library on the classpath (`dev.ujhhgtg:dexsql-natives-<os>-<arch>`), copied
 *    to a temporary file and loaded from there;
 * 4. `System.loadLibrary("dexsql_jni")`, which is what Android apps use with the `dexsql-android`
 *    AAR (the library ships in its `jniLibs`).
 *
 * Hosts that verify or relocate native libraries themselves can load the library first and then
 * call [load] with the same path, or call `System.loadLibrary` from a class in the same class
 * loader before touching [DexSqlBridge].
 */
@Suppress("UnsafeDynamicallyLoadedCode")
object DexSqlLibrary {
    const val LIBRARY_NAME = "dexsql_jni"
    const val PATH_PROPERTY = "dexsql.library.path"

    private val lock = Any()

    @Volatile private var loaded = false

    /** True after the native library has been loaded by this class loader. */
    val isLoaded: Boolean
        get() = loaded

    /**
     * Loads the library from an explicit [path]. Must be called before the first [DexSqlBridge]
     * operation; later calls are ignored once a library is loaded.
     */
    fun load(path: File) {
        synchronized(lock) {
            if (loaded) return
            System.load(path.absoluteFile.path)
            loaded = true
        }
    }

    internal fun ensureLoaded() {
        if (loaded) return
        synchronized(lock) {
            if (loaded) return
            val explicit = System.getProperty(PATH_PROPERTY)?.takeIf(String::isNotBlank)
            when {
                explicit != null -> System.load(File(explicit).absolutePath)
                else -> loadBundledOrSystem()
            }
            loaded = true
        }
    }

    private fun loadBundledOrSystem() {
        val resource = bundledResourcePath()
        val stream = resource?.let { DexSqlLibrary::class.java.getResourceAsStream(it) }
        if (stream == null) {
            System.loadLibrary(LIBRARY_NAME)
            return
        }
        val directory = createTempDirectory("dexsql-jni-")
        val target = directory / System.mapLibraryName(LIBRARY_NAME)
        stream.copyTo(target)
        target.deleteOnExit()
        directory.deleteOnExit()
        System.load(target.absolutePathString())
    }

    /** Copies this resource stream to [path], replacing a file left over from an earlier load. */
    private fun InputStream.copyTo(path: Path) {
        path.outputStream().use { outputStream ->
            this.use { it.copyTo(outputStream) }
        }
    }

    /** Kotlin-style form of [File.deleteOnExit] for a path. */
    private fun Path.deleteOnExit() = toFile().deleteOnExit()

    /** Classpath location used by the desktop natives jars, or null on unsupported hosts. */
    internal fun bundledResourcePath(): String? {
        val os = normalizedOs(System.getProperty("os.name").orEmpty()) ?: return null
        val arch = normalizedArch(System.getProperty("os.arch").orEmpty()) ?: return null
        return "/dev/ujhhgtg/dexsql/native/$os-$arch/" + System.mapLibraryName(LIBRARY_NAME)
    }

    internal fun normalizedOs(name: String): String? {
        val lower = name.lowercase()
        return when {
            lower.startsWith("linux") -> "linux"
            lower.startsWith("mac") || lower.startsWith("darwin") -> "macos"
            lower.startsWith("windows") -> "windows"
            else -> null
        }
    }

    internal fun normalizedArch(name: String): String? =
        when (name.lowercase()) {
            "amd64",
            "x86_64",
            "x64" -> "x86_64"
            "aarch64",
            "arm64" -> "aarch64"
            else -> null
        }
}
