package dev.ujhhgtg.dexsql.matcher

import dev.ujhhgtg.dexsql.meta.DexMetadata
import dev.ujhhgtg.dexsql.meta.DexMetadataKind
import dev.ujhhgtg.dexsql.meta.DexMethodInfo
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ShallowMethodEvaluationTest {
    private fun shallowRun(metadata: DexMetadata): DexMethodInfo {
        val document =
            MatcherFixtures.provider.query(DexMetadataKind.Method, MatcherFixtures.ALPHA_RUN)!!
        return DexMethodInfo(
            JsonObject(
                document.filterKeys {
                    it !in setOf("invokes", "using_fields", "using_strings", "using_numbers")
                },
            ),
            metadata,
        )
    }

    @Test
    fun scalarMatcherDoesNotReadUnconstrainedMethodRelations() {
        val metadata = DexMetadata { _, descriptor ->
            error("unexpected metadata read: $descriptor")
        }
        val evaluator = DexMatcherEvaluator(metadata)
        assertTrue(evaluator.matchesMethod(shallowRun(metadata), methodSpec { name = "run" }))
    }

    @Test
    fun callerStringConstraintsUseSqlOnceWithoutLoadingCallerDocuments() {
        val reads = mutableListOf<String>()
        val metadata = DexMetadata { kind, descriptor ->
            reads += descriptor
            check(descriptor != MatcherFixtures.ALPHA_RUN) { "caller document must stay shallow" }
            MatcherFixtures.provider.query(kind, descriptor)
        }
        val caller = shallowRun(metadata)
        val relations =
            object : DexMatcherRelations {
                override fun callers(methodDescriptor: String): List<DexMethodInfo> = listOf(caller)

                override fun fieldAccessMethods(
                    fieldDescriptor: String,
                    usingType: String,
                ): List<DexMethodInfo> = emptyList()
            }
        val query = RecordingDescriptorQuery { sql ->
            if (sql.contains("method_strings")) {
                if (sql.contains("missing")) emptyList() else listOf(MatcherFixtures.ALPHA_RUN)
            } else {
                listOf(MatcherFixtures.CALL_HELPER)
            }
        }
        val scope = QueryMatcherScope(metadata, query, relations)
        val spec = methodSpec {
            name = "helper"
            callerMethod { usingEqStrings("alpha marker", "marker") }
        }
        repeat(2) {
            assertEquals(MatcherFixtures.CALL_HELPER, scope.uniqueMethod(spec))
        }
        assertEquals(2, query.queries.count { it.contains("method_strings") })
        assertFalse(reads.contains(MatcherFixtures.ALPHA_RUN))
        val missing = spec.copy(callerMethods = listOf(methodSpec { usingEqStrings("missing") }))
        assertTrue(scope.findMethods(missing).isEmpty())
    }

    @Test
    fun requestedRelationsStillLoadFullMethodDocuments() {
        var reads = 0
        val metadata = DexMetadata { kind, descriptor ->
            reads++
            MatcherFixtures.provider.query(kind, descriptor)
        }
        val evaluator = DexMatcherEvaluator(metadata)
        assertTrue(
            evaluator.matchesMethod(
                shallowRun(metadata),
                methodSpec { usingEqStrings("alpha marker") },
            ),
        )
        assertEquals(1, reads)
    }

    @Test
    fun callerMatchingRemainsInjective() {
        val metadata = DexMetadata { kind, descriptor ->
            check(descriptor != MatcherFixtures.ALPHA_RUN)
            MatcherFixtures.provider.query(kind, descriptor)
        }
        val caller = shallowRun(metadata)
        val relations =
            object : DexMatcherRelations {
                override fun callers(methodDescriptor: String): List<DexMethodInfo> = listOf(caller)

                override fun fieldAccessMethods(
                    fieldDescriptor: String,
                    usingType: String,
                ): List<DexMethodInfo> = emptyList()
            }
        val query = RecordingDescriptorQuery { sql ->
            if (sql.contains("method_strings")) listOf(MatcherFixtures.ALPHA_RUN)
            else listOf(MatcherFixtures.CALL_HELPER)
        }
        val scope = QueryMatcherScope(metadata, query, relations)
        val spec = methodSpec {
            name = "helper"
            callerMethod { usingEqStrings("alpha marker") }
            callerMethod { usingEqStrings("alpha marker") }
        }
        assertTrue(scope.findMethods(spec).isEmpty())
    }
}
