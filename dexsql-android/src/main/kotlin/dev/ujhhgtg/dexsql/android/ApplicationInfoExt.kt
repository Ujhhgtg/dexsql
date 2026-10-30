package dev.ujhhgtg.dexsql.android

import android.content.pm.ApplicationInfo
import dev.ujhhgtg.dexsql.DexSqlBridge

/** The base APK followed by every installed split APK, in order and without duplicates. */
val ApplicationInfo.apkPaths: List<String>
    get() = buildList {
        add(sourceDir)
        splitSourceDirs.orEmpty().forEach(::add)
    }
        .filter { !it.isNullOrEmpty() }
        .distinct()

/** Open an installed application's base and split APKs as one dataset. */
fun DexSqlBridge.Companion.open(applicationInfo: ApplicationInfo): DexSqlBridge =
    open(applicationInfo.apkPaths)
