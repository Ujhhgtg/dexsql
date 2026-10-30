package dev.ujhhgtg.dexsql

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** Owned, allocation-safe representation of one DexSQL query result. */
data class DexSqlQueryResult(val columns: List<String>, val rows: List<List<String>>)

/** A native operation reported an error in its JSON envelope. */
class DexSqlException(message: String) : IllegalStateException(message)

/** Native returned malformed or incomplete JSON. */
class DexSqlProtocolException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/**
 * Kotlin owner for one native DexSQL dataset.
 *
 * A bridge may be shared by callers. Queries use the read side of a lifecycle lock, while [close]
 * takes the write side and therefore waits for in-flight calls before releasing the native handle.
 * Closing is idempotent; every other operation after close fails loudly. Prefer
 * `DexSqlBridge.open(...).use { ... }` so the native dataset is always released.
 *
 * This class only runs queries. Which row is "the" answer, and whether an empty result is an
 * expected failure, is caller policy.
 *
 * The native library is located by [DexSqlLibrary] on first use.
 */
class DexSqlBridge private constructor(handle: Long) : AutoCloseable {
    private val lifecycleLock = ReentrantReadWriteLock()
    private var nativeHandle = handle

    /** True while the native session is open. */
    val isOpen: Boolean
        get() = lifecycleLock.read { nativeHandle != 0L }

    /** Execute a read-only SQL statement and decode its structured result. */
    fun query(sql: String): DexSqlQueryResult = withHandle { handle ->
        decodeQuery(DexSqlNative.query(handle, sql))
    }

    /** Exception-free convenience form for callers that already use Kotlin [Result]. */
    fun queryResult(sql: String): Result<DexSqlQueryResult> = runCatching { query(sql) }

    /**
     * Read one indexed metadata document for a class, method or field descriptor. Missing
     * descriptors return null; malformed requests or native failures throw.
     */
    fun metadata(kind: String, descriptor: String): JsonObject? = withHandle { handle ->
        decodeMetadata(DexSqlNative.metadata(handle, kind, descriptor))
    }

    /** Caller list for one method descriptor; opt-in because pathological methods can be huge. */
    fun metadataCallers(descriptor: String): JsonElement? = withHandle { handle ->
        decodeMetadataCallers(DexSqlNative.metadataCallers(handle, descriptor))
    }

    override fun close() {
        val writeLock = lifecycleLock.writeLock()
        writeLock.lock()
        try {
            val handle = nativeHandle
            if (handle != 0L) {
                nativeHandle = 0L
                decodeEnvelope(DexSqlNative.close(handle), "close")
            }
        } finally {
            writeLock.unlock()
        }
    }

    private inline fun <T> withHandle(action: (Long) -> T): T = lifecycleLock.read {
        val handle = nativeHandle
        check(handle != 0L) { "DexSQL bridge is closed" }
        action(handle)
    }

    companion object {
        private val json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
        }

        /** Open one or more DEX/APK/JAR/ZIP paths. */
        fun open(paths: Iterable<String>): DexSqlBridge {
            val inputs = paths.filter(String::isNotEmpty).distinct()
            require(inputs.isNotEmpty()) { "DexSQL requires at least one input path" }
            val response = decodeEnvelope(DexSqlNative.open(inputs.toTypedArray()), "open")
            val handle =
                response.handle?.takeIf { it > 0L }
                    ?: throw DexSqlProtocolException("DexSQL open response omitted the handle")
            return DexSqlBridge(handle)
        }

        /** Open one or more DEX/APK/JAR/ZIP paths. */
        fun open(vararg paths: String): DexSqlBridge = open(paths.asIterable())

        private fun decodeMetadata(raw: String): JsonObject? {
            val response = decodeEnvelope(raw, "metadata")
            return response.metadata as? JsonObject
        }

        private fun decodeMetadataCallers(raw: String): JsonElement? {
            val response = decodeEnvelope(raw, "metadataCallers")
            return response.callers
        }

        private fun decodeQuery(raw: String): DexSqlQueryResult {
            val response = decodeEnvelope(raw, "query")
            if (response.columns == null || response.rows == null) {
                throw DexSqlProtocolException("DexSQL query response omitted columns or rows")
            }
            return DexSqlQueryResult(response.columns, response.rows)
        }

        private fun decodeEnvelope(raw: String, operation: String): NativeResponse {
            val response =
                try {
                    json.decodeFromString<NativeResponse>(raw)
                } catch (error: Throwable) {
                    throw DexSqlProtocolException(
                        "DexSQL $operation returned malformed JSON: " +
                            (error.message ?: error.javaClass.simpleName),
                        error,
                    )
                }
            if (!response.ok) {
                val error = response.error
                throw DexSqlException(
                    error?.message ?: error?.kind ?: "DexSQL $operation failed",
                )
            }
            return response
        }
    }

    @Serializable
    private data class NativeResponse(
        val ok: Boolean,
        val handle: Long? = null,
        val columns: List<String>? = null,
        val rows: List<List<String>>? = null,
        val metadata: JsonElement? = null,
        val callers: JsonElement? = null,
        val error: NativeError? = null,
    )

    @Serializable
    private data class NativeError(val kind: String? = null, val message: String? = null)
}
