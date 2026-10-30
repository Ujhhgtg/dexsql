package dev.ujhhgtg.dexsql

import dev.ujhhgtg.dexsql.matcher.DexMatcherSession
import dev.ujhhgtg.dexsql.sql.sqlMethod
import java.io.File
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** End-to-end tests through the real JNI library against the committed DEX fixtures. */
class DexSqlBridgeTest {
    private val fixtures = File(System.getProperty("dexsql.fixtures") ?: "../fixtures/dex")

    private fun open(): DexSqlBridge =
        DexSqlBridge.open(listOf("alpha.dex", "beta.dex").map { fixtures.resolve(it).path })

    @Test
    fun bundledLibraryResourceIsResolved() {
        assertEquals(
            "/dev/ujhhgtg/dexsql/native/linux-x86_64/libdexsql_jni.so",
            DexSqlLibrary.bundledResourcePath(),
        )
    }

    @Test
    fun queryReturnsColumnsAndRows() {
        open().use { bridge ->
            val result =
                bridge.query(
                    "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm " +
                        "WHERE instr(cm.class_descriptor, 'Lfixtures/') = 1 " +
                        "ORDER BY cm.class_descriptor",
                )
            assertEquals(listOf("descriptor"), result.columns)
            assertEquals(
                listOf("Lfixtures/Alpha;", "Lfixtures/Beta;", "Lfixtures/Gamma;"),
                result.rows.map { it.single() },
            )
        }
    }

    @Test
    fun sqlDslRunsAgainstTheEngine() {
        open().use { bridge ->
            val sql = sqlMethod {
                declaredClass = "fixtures.Alpha"
                usingEqStrings("alpha-two")
            }
                .toSql()
            assertEquals(
                listOf("Lfixtures/Alpha;->duplicateStrings()I"),
                bridge.query(sql).rows.map { it.single() },
            )
        }
    }

    @Test
    fun metadataAndCallersAreDecoded() {
        open().use { bridge ->
            val alpha = bridge.metadata("class", "Lfixtures/Alpha;")!!
            assertEquals("fixtures.Alpha", alpha["name"]!!.jsonPrimitive.content)
            assertNull(bridge.metadata("class", "Ldoes/Not/Exist;"))

            val callers = bridge.metadataCallers("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I")!!
            assertEquals(
                listOf("Lfixtures/Alpha;->doIt()V", "Lfixtures/Beta;->run()V"),
                callers.jsonArray.map { it.jsonObject["descriptor"]!!.jsonPrimitive.content },
            )
        }
    }

    @Test
    fun matcherSessionFindsMembers() {
        open().use { bridge ->
            DexMatcherSession(bridge).use { session ->
                val methods = session.findMethods {
                    declaredClass("fixtures.Alpha")
                    usingStrings("alpha-two")
                }
                assertEquals(
                    listOf("Lfixtures/Alpha;->duplicateStrings()I"),
                    methods.map { it.descriptor },
                )
                val callers = session.callers("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I")
                assertEquals(
                    setOf("Lfixtures/Alpha;->doIt()V", "Lfixtures/Beta;->run()V"),
                    callers.map { it.descriptor }.toSet(),
                )
            }
        }
    }

    @Test
    fun nonAsciiStringsRoundTrip() {
        open().use { bridge ->
            val result = bridge.query("SELECT '微信 😀' AS value")
            assertEquals(listOf(listOf("微信 😀")), result.rows)
        }
    }

    @Test
    fun errorsAreReportedAsExceptions() {
        assertThrows(DexSqlException::class.java) {
            DexSqlBridge.open(listOf(fixtures.resolve("missing.dex").path))
        }
        assertThrows(IllegalArgumentException::class.java) { DexSqlBridge.open(emptyList()) }
        open().use { bridge ->
            assertThrows(DexSqlException::class.java) { bridge.query("SELECT FROM WHERE") }
            assertThrows(DexSqlException::class.java) { bridge.metadata("module", "La;") }
            assertTrue(bridge.queryResult("SELECT FROM WHERE").isFailure)
        }
    }

    @Test
    fun closeIsIdempotentAndBlocksFurtherUse() {
        val bridge = open()
        assertTrue(bridge.isOpen)
        bridge.close()
        bridge.close()
        assertFalse(bridge.isOpen)
        assertThrows(IllegalStateException::class.java) { bridge.query("SELECT 1") }
    }
}
