package dev.ujhhgtg.dexsql.sql

import dev.ujhhgtg.dexsql.matcher.ClassSpec
import dev.ujhhgtg.dexsql.matcher.FieldSpec
import dev.ujhhgtg.dexsql.matcher.MethodSpec
import dev.ujhhgtg.dexsql.matcher.NameMatch
import dev.ujhhgtg.dexsql.matcher.NameSpec
import dev.ujhhgtg.dexsql.matcher.OpcodeMatchType
import dev.ujhhgtg.dexsql.meta.FieldUsingType
import dev.ujhhgtg.dexsql.meta.javaNameToDescriptor

internal class ComposedSpecSql {
    private var nextAlias = 0

    private fun alias(): String = "q" + nextAlias++

    private fun and(predicates: List<String>): String =
        if (predicates.isEmpty()) "1 = 1" else predicates.joinToString(" AND ") { "($it)" }

    private fun select(
        table: String,
        owner: String,
        column: String,
        predicates: List<String>,
    ): String = "SELECT DISTINCT $owner.$column FROM $table $owner WHERE ${and(predicates)}"

    private fun methodSet(spec: MethodSpec, column: String = "descriptor"): String {
        val query = spec.toSqlMethodQueryOrNull()
        if (query != null) {
            return emitMethod(query, false, column).trimEnd(';')
        }
        val target = alias()
        return select("methods", target, column, methodPredicates(spec, target))
    }

    private fun classSet(spec: ClassSpec): String {
        spec.toSqlClassQueryOrNull()?.let {
            return emitClass(it).trimEnd(';')
        }
        val target = alias()
        return select("classes", target, "descriptor", classPredicates(spec, target))
    }

    fun method(spec: MethodSpec, constructor: Boolean = false): String {
        val owner = alias()
        val effective = if (constructor) spec.copy(name = NameSpec("<init>")) else spec
        require(!constructor || spec.name == null || spec.name == NameSpec("<init>"))
        return select("methods", owner, "descriptor", methodPredicates(effective, owner)) +
            " ORDER BY $owner.descriptor;"
    }

    fun clazz(spec: ClassSpec): String {
        val owner = alias()
        return select("classes", owner, "descriptor", classPredicates(spec, owner)) +
            " ORDER BY $owner.descriptor;"
    }

    fun field(spec: FieldSpec): String {
        val owner = alias()
        return select("fields", owner, "descriptor", fieldPredicates(spec, owner)) +
            " ORDER BY $owner.descriptor;"
    }

    private fun name(column: String, value: String, match: NameMatch): String =
        if (value.isEmpty() && match != NameMatch.Equals) "$column IS NOT NULL"
        else
            when (match) {
                NameMatch.Equals -> "$column = ${sqlQuote(value)}"
                NameMatch.StartsWith -> "instr($column, ${sqlQuote(value)}) = 1"
                NameMatch.Contains -> "instr($column, ${sqlQuote(value)}) > 0"
                NameMatch.EndsWith ->
                    "substr($column, -${value.codePointCount(0, value.length)}) = ${sqlQuote(value)}"
            }

    private fun typeName(column: String, spec: NameSpec): String =
        if (spec.match == NameMatch.Equals) {
            "$column = ${sqlQuote(javaNameToDescriptor(spec.value))}"
        } else {
            name("dex_java_name($column)", spec.value, spec.match)
        }

    private fun packages(
        column: String,
        include: List<String>,
        exclude: List<String>,
    ): List<String> {
        fun group(values: List<String>): String =
            values.joinToString(" OR ") {
                val prefix = "L" + it.replace('.', '/').trim('/')
                "($column = ${sqlQuote("$prefix;")} OR instr($column, ${sqlQuote("$prefix/")}) = 1)"
            }
        return buildList {
            if (include.isNotEmpty()) add("(" + group(include) + ")")
            if (exclude.isNotEmpty()) add("NOT (" + group(exclude) + ")")
        }
    }

    private fun count(column: String, range: IntRange): String =
        "$column >= ${range.first} AND $column <= ${range.last}"

    private fun classReference(column: String, spec: ClassSpec): String {
        if (
            spec.className != null &&
                spec.copy(
                    className = null,
                    searchPackages = emptyList(),
                    excludePackages = emptyList(),
                ) == ClassSpec()
        ) {
            return and(
                buildList {
                    add(typeName(column, spec.className))
                    addAll(packages(column, spec.searchPackages, spec.excludePackages))
                },
            )
        }
        return "$column IN (${classSet(spec)})"
    }

    private fun methodPredicates(spec: MethodSpec, owner: String): List<String> = buildList {
        require(spec.annotations.isEmpty())
        spec.descriptor?.let { add("$owner.descriptor = ${sqlQuote(it)}") }
        spec.name?.let { add(name("$owner.name", it.value, it.match)) }
        spec.modifiers?.let { add("(coalesce($owner.access_flags, 0) & $it) = $it") }
        spec.paramCount?.let { add(count("$owner.param_count", it)) }
        spec.paramTypes?.let { types ->
            require(types.all { it == null || it.match == NameMatch.Equals })
            add(
                "param_types_match($owner.param_descriptors, ${sqlQuote(types.joinToString(",") { if (it == null) "?" else javaNameToDescriptor(it.value) })}) = 1",
            )
        }
        addAll(packages("$owner.class_descriptor", spec.searchPackages, spec.excludePackages))
        spec.declaredClass?.let { add(classReference("$owner.class_descriptor", it)) }
        spec.returnType?.let { add(classReference("$owner.return_descriptor", it)) }
        if (spec.usingStrings.isNotEmpty()) {
            val literals =
                spec.usingStrings.map { literal ->
                    if (literal.value.isEmpty()) literal.copy(match = NameMatch.Equals) else literal
                }
            add("$owner.descriptor IN (${methodSet(MethodSpec(usingStrings = literals))})")
        }
        if (spec.usingNumbers.isNotEmpty()) {
            add("$owner.descriptor IN (${methodSet(MethodSpec(usingNumbers = spec.usingNumbers))})")
        }
        addAll(
            injective(
                "$owner.descriptor",
                "method_calls",
                "method",
                spec.invokeMethods.map { nested ->
                    { relation: String ->
                        "$relation.callee IN (${methodSet(nested)})"
                    }
                },
            ),
        )
        addAll(
            injective(
                "$owner.descriptor",
                "method_calls",
                "callee",
                spec.callerMethods.map { nested ->
                    { relation: String ->
                        "$relation.method IN (${methodSet(nested)})"
                    }
                },
            ),
        )
        addAll(
            injective(
                "$owner.descriptor",
                "method_field_accesses",
                "method",
                spec.usingFields.map { access ->
                    { relation: String ->
                        val target = alias()
                        and(
                            buildList {
                                add(
                                    "$relation.field IN (${select("fields", target, "descriptor", fieldPredicates(access.field, target))})",
                                )
                                access.usingType?.let {
                                    add(
                                        "$relation.using_type = '${if (it == FieldUsingType.Read) "get" else "put"}'",
                                    )
                                }
                            },
                        )
                    }
                },
            ),
        )
        spec.allOf.forEach { add(and(methodPredicates(it, owner))) }
        if (spec.anyOf.isNotEmpty())
            add(spec.anyOf.joinToString(" OR ") { "(${and(methodPredicates(it, owner))})" })
        spec.opcodes?.let { opcodes ->
            add("$owner.opcode_hex IS NOT NULL")
            opcodes.count?.let { add(count("$owner.opcode_count", it)) }
            if (opcodes.names.isNotEmpty()) {
                val bytes =
                    opcodes.names.map { opcode ->
                        requireNotNull(OPCODE_BYTES[opcode]) { "Unknown opcode: $opcode" }
                    }
                if (opcodes.matchType == OpcodeMatchType.Equals) {
                    add("$owner.opcode_hex = ${sqlQuote(bytes.joinToString(" "))}")
                } else {
                    bytes.forEach {
                        add("instr(' ' || $owner.opcode_hex || ' ', ${sqlQuote(" $it ")}) > 0")
                    }
                }
            }
        }
    }

    private fun classPredicates(spec: ClassSpec, owner: String): List<String> = buildList {
        require(spec.annotations.isEmpty() && spec.annotationCount == null)
        spec.noneOf.forEach { add("NOT (${and(classPredicates(it, owner))})") }
        spec.className?.let { add(typeName("$owner.descriptor", it)) }
        addAll(packages("$owner.descriptor", spec.searchPackages, spec.excludePackages))
        spec.modifiers?.let { add("($owner.access_flags & $it) = $it") }
        spec.fieldCount?.let { add(count("$owner.field_count", it)) }
        spec.methodCount?.let { add(count("$owner.method_count", it)) }
        spec.interfaceCount?.let { add(count("$owner.interface_count", it)) }
        spec.superClass?.let { add(classReference("$owner.superclass_descriptor", it)) }
        addAll(
            injective(
                "$owner.descriptor",
                "class_interfaces",
                "class_descriptor",
                spec.interfaces.map { nested ->
                    { relation: String -> classReference("$relation.interface_descriptor", nested) }
                },
            ),
        )
        addAll(
            injective(
                "$owner.descriptor",
                "class_fields",
                "class_descriptor",
                spec.fields.map { nested ->
                    { relation: String ->
                        if (
                            nested.readMethods.isEmpty() &&
                                nested.writeMethods.isEmpty() &&
                                nested.annotations.isEmpty()
                        ) {
                            and(
                                buildList {
                                    nested.name?.let {
                                        add(name("$relation.field_name", it.value, it.match))
                                    }
                                    nested.type?.let {
                                        add(classReference("$relation.field_type", it))
                                    }
                                    nested.declaredClass?.let {
                                        add(classReference("$relation.class_descriptor", it))
                                    }
                                    nested.modifiers?.let {
                                        add("($relation.access_flags & $it) = $it")
                                    }
                                    addAll(
                                        packages(
                                            "$relation.class_descriptor",
                                            nested.searchPackages,
                                            nested.excludePackages,
                                        ),
                                    )
                                },
                            )
                        } else {
                            val target = alias()
                            "$relation.field_descriptor IN (${select("fields", target, "descriptor", fieldPredicates(nested, target))})"
                        }
                    }
                },
            ),
        )
        addAll(
            injective(
                "$owner.descriptor",
                "class_methods",
                "class_descriptor",
                spec.methods.map { nested ->
                    { relation: String ->
                        "$relation.method_descriptor IN (${methodSet(nested)})"
                    }
                },
            ),
        )
        spec.usingStrings.forEach { literal ->
            add(
                "$owner.descriptor IN (${methodSet(MethodSpec(usingStrings = listOf(literal)), "class_descriptor")})",
            )
        }
        spec.usingNumbers.forEach { number ->
            add(
                "$owner.descriptor IN (${methodSet(MethodSpec(usingNumbers = listOf(number)), "class_descriptor")})",
            )
        }
    }

    private fun fieldPredicates(spec: FieldSpec, owner: String): List<String> = buildList {
        require(spec.annotations.size <= 1)
        spec.annotations.singleOrNull()?.let { annotation ->
            val sql = requireNotNull(annotationOwnerSql("field", annotation))
            add("$owner.descriptor IN ($sql)")
        }
        spec.name?.let { add(name("$owner.name", it.value, it.match)) }
        addAll(packages("$owner.class_descriptor", spec.searchPackages, spec.excludePackages))
        spec.type?.let { add(classReference("$owner.type_descriptor", it)) }
        spec.declaredClass?.let { add(classReference("$owner.class_descriptor", it)) }
        spec.modifiers?.let { mask ->
            val target = alias()
            add(
                "$owner.descriptor IN (${select("class_fields", target, "field_descriptor", listOf("($target.access_flags & $mask) = $mask"))})",
            )
        }
        for ((direction, methods) in
            listOf("get" to spec.readMethods, "put" to spec.writeMethods)) {
            addAll(
                injective(
                    "$owner.descriptor",
                    "method_field_accesses",
                    "field",
                    methods.map { nested ->
                        { relation: String ->
                            "$relation.using_type = '$direction' AND $relation.method IN (${methodSet(nested)})"
                        }
                    },
                    distinct = "method",
                ),
            )
        }
    }

    private fun injective(
        column: String,
        table: String,
        key: String,
        predicates: List<(String) -> String>,
        distinct: String? = null,
    ): List<String> {
        if (predicates.isEmpty()) return emptyList()
        val relation = alias()
        val units = predicates.map { it(relation) }.groupingBy { it }.eachCount().entries.toList()
        require(units.size < 16)
        return (1 until (1 shl units.size)).map { mask ->
            val selected = units.indices.filter { mask and (1 shl it) != 0 }
            val required = selected.sumOf { units[it].value }
            val filter = selected.joinToString(" OR ") { "(${units[it].key})" }
            val group =
                if (required == 1) ""
                else
                    " GROUP BY $relation.$key HAVING count(${if (distinct == null) "*" else "DISTINCT $relation.$distinct"}) >= $required"
            "$column IN (SELECT $relation.$key FROM $table $relation WHERE $filter$group)"
        }
    }
}
