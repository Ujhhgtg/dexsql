package dev.ujhhgtg.dexsql

/**
 * The JNI surface exported by `libdexsql_jni`.
 *
 * Every operation returns a JSON envelope, `{ok:true,...}` or `{ok:false,error:{kind,message}}`;
 * native code never throws into the JVM. Keeping this object free of Kotlin logic keeps the JNI
 * names (`Java_dev_ujhhgtg_dexsql_DexSqlNative_*`) stable when [DexSqlBridge] changes.
 *
 * The engine executes read-only SQL only. Row selection and result classification (single row,
 * expected failure, ...) are caller concerns.
 */
internal object DexSqlNative {
    init {
        DexSqlLibrary.ensureLoaded()
    }

    /** Envelope: `{ok:true, handle:<long>}`. */
    external fun open(paths: Array<String>): String

    /** Envelope: `{ok:true, columns:[...], rows:[[...]]}`. */
    external fun query(handle: Long, sql: String): String

    /** Envelope: `{ok:true, metadata:<object|null>}`; [kind] is class/method/field. */
    external fun metadata(handle: Long, kind: String, descriptor: String): String

    /** Envelope: `{ok:true, callers:<array|null>}` for one method descriptor. */
    external fun metadataCallers(handle: Long, descriptor: String): String

    /** Envelope: `{ok:true, closed:true}`. */
    external fun close(handle: Long): String
}
