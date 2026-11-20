package dev.ujhhgtg.dexsql.matcher

import dev.ujhhgtg.dexsql.DexSqlBridge
import dev.ujhhgtg.dexsql.sql.toSqlOrNull
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FieldAnnotationMatcherTest {
    @Test
    fun fieldAnnotationNarrowsDirectAndNestedQueries() {
        val fixtures = File(System.getProperty("dexsql.fixtures"))
        val field = fieldSpec {
            type("java.lang.String")
            annotation {
                type("fixtures.FieldAnnotations\$Serialized")
                element("value", "message")
            }
        }
        val owner = classSpec { field(field) }
        val method = methodSpec {
            declaredClass(owner)
            returnType("java.lang.String")
            readField(field)
        }
        DexSqlBridge.open(fixtures.resolve("field-annotations.dex").path).use { bridge ->
            DexMatcherSession(bridge).use { session ->
                assertEquals(listOf("text"), session.findFields(field).map { it.name })
                assertEquals(
                    listOf("fixtures.FieldAnnotations"),
                    session.findClasses(owner).map { it.name },
                )
                assertEquals(listOf("read"), session.findMethods(method).map { it.name })
                for ((sql, expected) in
                    listOf(
                        field.toSqlOrNull() to
                            "Lfixtures/FieldAnnotations;->text:Ljava/lang/String;",
                        owner.toSqlOrNull() to "Lfixtures/FieldAnnotations;",
                        method.toSqlOrNull() to
                            "Lfixtures/FieldAnnotations;->read()Ljava/lang/String;",
                    )) {
                    assertEquals(listOf(listOf(expected)), bridge.query(requireNotNull(sql)).rows)
                }
            }
        }
    }
}
