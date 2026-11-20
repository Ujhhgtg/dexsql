package dev.ujhhgtg.dexsql.sql

import dev.ujhhgtg.dexsql.matcher.AnnotationSpec
import dev.ujhhgtg.dexsql.matcher.AnnotationValue
import dev.ujhhgtg.dexsql.matcher.AnnotationVisibility
import dev.ujhhgtg.dexsql.matcher.NameMatch
import dev.ujhhgtg.dexsql.matcher.NameSpec
import dev.ujhhgtg.dexsql.meta.javaNameToDescriptor

internal fun annotationOwnerSql(
    kind: String,
    spec: AnnotationSpec,
): String? {
    require(kind in setOf("class", "method", "field"))
    if (spec.elements.size > 1) return null
    val element = spec.elements.singleOrNull()
    val value = element?.value as? AnnotationValue.Text
    if (
        element != null &&
            (value == null ||
                element.name.match != NameMatch.Equals &&
                    element.name != NameSpec("", NameMatch.Contains))
    )
        return null
    val predicates = mutableListOf("ar.owner_kind = '$kind'")
    spec.type?.let { type ->
        if (type.match != NameMatch.Equals) return null
        predicates += "ar.annotation = ${sqlQuote(javaNameToDescriptor(type.value))}"
    }
    spec.visibility?.let { visibility ->
        val encoded =
            when (visibility) {
                AnnotationVisibility.Build -> 0
                AnnotationVisibility.Runtime -> 1
                AnnotationVisibility.System -> 2
                AnnotationVisibility.Unknown -> return null
            }
        predicates += "ar.visibility = $encoded"
    }
    val joins =
        if (value == null) ""
        else {
            if (element.name.match == NameMatch.Equals) {
                predicates += "ar.element_name = ${sqlQuote(element.name.value)}"
            }
            predicates += "ar.value_kind = 'string'"
            val literal = sqlQuote(value.value)
            predicates +=
                when {
                    value.value.isEmpty() || value.match == NameMatch.Equals -> "s.value = $literal"
                    value.match == NameMatch.Contains -> "instr(s.value, $literal) > 0"
                    value.match == NameMatch.StartsWith -> "instr(s.value, $literal) = 1"
                    else ->
                        "substr(s.value, -${value.value.codePointCount(0, value.value.length)}) = $literal"
                }
            " JOIN dex_files d ON d.file_id = ar.file_id" +
                " JOIN strings s ON s.string_pool_id = d.string_pool_id AND s.string_idx = ar.value_index"
        }
    return "SELECT DISTINCT ar.owner AS descriptor FROM annotation_elements_resolved ar$joins " +
        "WHERE ${predicates.joinToString(" AND ")} ORDER BY ar.owner"
}
