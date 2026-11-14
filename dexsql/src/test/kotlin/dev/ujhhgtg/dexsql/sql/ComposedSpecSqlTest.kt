package dev.ujhhgtg.dexsql.sql

import dev.ujhhgtg.dexsql.DexSqlBridge
import dev.ujhhgtg.dexsql.DexSqlMetadataProvider
import dev.ujhhgtg.dexsql.matcher.BridgeMatcherRelations
import dev.ujhhgtg.dexsql.matcher.ClassSpec
import dev.ujhhgtg.dexsql.matcher.DexMatcherEvaluator
import dev.ujhhgtg.dexsql.matcher.FieldSpec
import dev.ujhhgtg.dexsql.matcher.MethodSpec
import dev.ujhhgtg.dexsql.matcher.OpcodeMatchType
import dev.ujhhgtg.dexsql.matcher.classSpec
import dev.ujhhgtg.dexsql.matcher.fieldSpec
import dev.ujhhgtg.dexsql.matcher.methodSpec
import dev.ujhhgtg.dexsql.meta.DexMetadata
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

class ComposedSpecSqlTest {
    private fun withBridge(block: (DexSqlBridge, DexMetadata, DexMatcherEvaluator) -> Unit) {
        val fixtures = File(System.getProperty("dexsql.fixtures"))
        DexSqlBridge.open(listOf("alpha.dex", "beta.dex").map { File(fixtures, it).path }).use {
            bridge ->
            val provider = DexSqlMetadataProvider(bridge)
            val metadata = DexMetadata(provider)
            val relations = BridgeMatcherRelations(provider::callers, bridge::query, metadata)
            block(bridge, metadata, DexMatcherEvaluator(metadata, relations))
        }
    }

    private fun methodParity(spec: MethodSpec) = withBridge { bridge, metadata, evaluator ->
        val expected =
            bridge
                .query("SELECT DISTINCT descriptor FROM methods")
                .rows
                .map { it.single() }
                .filter { evaluator.matchesMethod(metadata.methodInfo(it)!!, spec) }
                .sorted()
        val sql = requireNotNull(spec.toSqlOrNull())
        assertEquals(expected, bridge.query(sql).rows.map { it.single() }, sql)
    }

    private fun classParity(spec: ClassSpec) = withBridge { bridge, metadata, evaluator ->
        val expected =
            bridge
                .query("SELECT DISTINCT descriptor FROM classes")
                .rows
                .map { it.single() }
                .filter { evaluator.matchesClass(metadata.classInfo(it)!!, spec) }
                .sorted()
        val sql = requireNotNull(spec.toSqlOrNull())
        assertEquals(expected, bridge.query(sql).rows.map { it.single() }, sql)
    }

    private fun fieldParity(spec: FieldSpec) = withBridge { bridge, metadata, evaluator ->
        val expected =
            bridge
                .query("SELECT DISTINCT descriptor FROM fields")
                .rows
                .map { it.single() }
                .filter { evaluator.matchesField(metadata.fieldInfo(it)!!, spec) }
                .sorted()
        val sql = requireNotNull(spec.toSqlOrNull())
        assertEquals(expected, bridge.query(sql).rows.map { it.single() }, sql)
    }

    @Test
    fun duplicateInvokeEntriesRemainAvailableForInjectiveMatching() {
        for (count in listOf(1, 2, 3)) methodParity(
            methodSpec {
                declaredClass = "fixtures.Alpha"
                repeat(count) { invokeMethod { name = "helper" } }
            },
        )
    }

    @Test
    fun callsResolveExternalSignaturesAndCrossDexLiterals() {
        methodParity(
            methodSpec {
                searchPackages("fixtures")
                invokeMethod {
                    declaredClass = "java.io.PrintStream"
                    paramTypes("java.lang.String")
                }
            },
        )
        methodParity(
            methodSpec {
                declaredClass = "fixtures.Beta"
                invokeMethod { declaredClass { usingString("alpha") } }
            },
        )
        methodParity(
            methodSpec {
                declaredClass = "fixtures.Alpha"
                callerMethod { declaredClass = "fixtures.Beta" }
            },
        )
    }

    @Test
    fun structuralClassTypeAndMixedMemberConstraintsCompose() {
        classParity(
            classSpec {
                className = "fixtures.Alpha"
                field { type = "java.lang.String" }
                field { type = "java.lang.String" }
                method { returnType = "int" }
            },
        )
        classParity(
            classSpec {
                superClass { field { type = "int" } }
            },
        )
        methodParity(
            methodSpec {
                declaredClass { interfaceSpec { className = "fixtures.Gamma" } }
                returnType = "void"
            },
        )
        fieldParity(
            fieldSpec {
                type { method { name = "add" } }
            },
        )
    }

    @Test
    fun overlappingMemberPredicatesRequireDifferentMembers() {
        for (count in listOf(2, 3)) classParity(
            classSpec {
                className = "fixtures.Alpha"
                repeat(count) { field { type = "java.lang.String" } }
                method { name = "greet" }
            },
        )
        classParity(
            classSpec {
                className = "fixtures.Alpha"
                field { type = "java.lang.String" }
                field { name = "TAG" }
                field { name = "TAG" }
                method { name = "greet" }
            },
        )
    }

    @Test
    fun repeatedReaderConstraintsDoNotCountDuplicateAccessInstructions() {
        fieldParity(
            fieldSpec {
                declaredClass = "fixtures.Alpha"
                readMethod { name = "fieldTraffic" }
                readMethod { name = "fieldTraffic" }
            },
        )
    }

    @Test
    fun fieldModifiersAndFieldOwnersMatchTheMetadataView() {
        fieldParity(
            fieldSpec {
                declaredClass = "fixtures.Alpha"
                modifiers = 8
            },
        )
        methodParity(
            methodSpec {
                declaredClass = "fixtures.Alpha"
                readField {
                    declaredClass = "fixtures.Alpha"
                    type = "int"
                }
            },
        )
    }

    @Test
    fun booleanAlternativesKeepIndependentLiteralScopes() {
        methodParity(
            methodSpec {
                declaredClass = "fixtures.Alpha"
                anyOf { name = "helper" }
                anyOf { invokeMethod { name = "println" } }
                allOf { returnType = "int" }
            },
        )
    }

    @Test
    fun namedOpcodesAndCountConstraintsComposeInNestedMethods() {
        classParity(
            classSpec {
                method {
                    opcodes(names = listOf("new-instance"), matchType = OpcodeMatchType.Contains)
                }
            },
        )
        methodParity(
            methodSpec {
                declaredClass = "fixtures.Alpha"
                opcodes(names = listOf("return-void"), matchType = OpcodeMatchType.Equals)
            },
        )
    }

    @Test
    fun returnTypeOnlyNestedMethodsAreSqlPredicates() {
        val spec = classSpec {
            className = "fixtures.Alpha"
            method { returnType = "int" }
        }
        assertNotNull(spec.toSqlOrNull())
        classParity(spec)
    }
}
