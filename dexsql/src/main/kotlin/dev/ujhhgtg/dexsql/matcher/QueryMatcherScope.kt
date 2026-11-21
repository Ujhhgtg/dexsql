package dev.ujhhgtg.dexsql.matcher

import dev.ujhhgtg.dexsql.DexSqlException
import dev.ujhhgtg.dexsql.meta.DexClassInfo
import dev.ujhhgtg.dexsql.meta.DexFieldInfo
import dev.ujhhgtg.dexsql.meta.DexMetadata
import dev.ujhhgtg.dexsql.meta.DexMetadataKind
import dev.ujhhgtg.dexsql.meta.DexMethodInfo
import dev.ujhhgtg.dexsql.meta.descriptorToJavaName
import dev.ujhhgtg.dexsql.sql.SqlClassLiteralConstraint
import dev.ujhhgtg.dexsql.sql.SqlClassQuery
import dev.ujhhgtg.dexsql.sql.SqlFieldQuery
import dev.ujhhgtg.dexsql.sql.SqlMethodQuery
import dev.ujhhgtg.dexsql.sql.SqlStringMatchMode
import dev.ujhhgtg.dexsql.sql.annotationOwnerSql
import dev.ujhhgtg.dexsql.sql.sqlClass
import dev.ujhhgtg.dexsql.sql.sqlField
import dev.ujhhgtg.dexsql.sql.sqlMethod
import dev.ujhhgtg.dexsql.sql.sqlQuote
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/** Executes one generated candidate query and returns the descriptors from its first column. */
fun interface DexDescriptorQuery {
    fun descriptors(sql: String): List<String>
}

private const val DEFAULT_CANDIDATE_PAGE_SIZE = 4096

/** Class candidates closer to this bound are good enough; larger sets are intersected. */
private const val NESTED_CANDIDATE_INTERSECTION_THRESHOLD = 32

/**
 * Broad library types that must not drive class candidates when used as a bare type-only field
 * (dotted form, plus primitives/arrays handled separately). Dynamic/obfuscated/domain class names
 * outside this set are considered narrow.
 */
private val BROAD_FIELD_TYPE_NAMES =
    setOf(
        "java.lang.Object",
        "java.lang.String",
        "java.lang.CharSequence",
        "java.lang.Class",
        "java.util.List",
        "java.util.Map",
        "java.util.Set",
        "android.view.View",
        "android.widget.TextView",
    )

/**
 * Broad builtin field-type prefixes: a type-only field matcher in these namespaces is not selective
 * enough to drive a field candidate when a read/write-method two-step source exists. Used only for
 * field specs (the class-candidate narrow-type policy uses the exact BROAD_FIELD_TYPE_NAMES set).
 */
private val BROAD_FIELD_TYPE_PREFIXES =
    listOf(
        "java.",
        "javax.",
        "android.",
        "androidx.",
        "kotlin.",
        "kotlinx.",
        "org.jetbrains.",
        "sun.",
        "dalvik.",
    )

/** One candidate source: canonical SQL text (paged) or a known-short descriptor list. */
private sealed interface CandidateSource {
    class Sql(val sql: String) : CandidateSource

    class Descriptors(val descriptors: List<String>) : CandidateSource
}

/**
 * Query-backed matcher scope: generates candidate sets only through canonical DexSQL fast-path
 * shapes (the same shapes the SQL DSL emits), then evaluates the full DexKit matcher semantics over
 * the metadata API.
 *
 * Candidate generation rules (the pinned engine only fast-paths canonical shapes):
 * - method specs use the typed SQL DSL (methods x method_strings / method_using_numbers /
 *   method_field_accesses canonical joins with single-equality ON + file_id/method_idx WHERE);
 * - structural constraints (declaredClass/returnType class structure, invokeMethods, usingFields,
 *   callerMethods) are evaluated in Kotlin, never joined in SQL;
 * - class specs use className/searchPackages/class-level literals through the DSL; a class whose
 *   only cheap predicate is class-level usingStrings (or a nested cheap member) is narrowed in two
 *   steps: canonical method/field lookup, then map the candidate's declared class and evaluate;
 * - field specs use name/type/declaredClass/searchPackages through the DSL.
 *
 * A spec with no fast-path-expressible predicate is an explicit unsupported-shape error instead of
 * a multi-gigabyte generic table scan.
 *
 * unique* helpers stop as soon as a second match is found and page SQL candidates, so the amount of
 * evaluated work/cache growth is bounded. Raw documents are read through [rawMetadata] and cheap
 * scalar prefilters run before a parsed metadata model is constructed (rejected candidates never
 * enter the session cache).
 */
class QueryMatcherScope(
    val metadata: DexMetadata,
    private val query: DexDescriptorQuery,
    val relations: DexMatcherRelations? = null,
    /** Raw metadata document reader; lets cheap prefilters run before model construction. */
    private val rawMetadata: ((DexMetadataKind, String) -> JsonObject?)? = null,
    private val candidatePageSize: Int = DEFAULT_CANDIDATE_PAGE_SIZE,
    /** Cross-delegate session caches (null in unit tests: per-scope caches are used instead). */
    private val sessionCache: MatcherSessionCache? = null,
) {
    private val localStringClasses = HashMap<String, Set<String>>()
    private val localStringMethods = HashMap<StringSpec, Set<String>>()
    private val classMatchCache = HashMap<Pair<String, ClassSpec>, Boolean>()

    // Candidate queries are executed at most once per resolution scope for small result sets; the
    // two-step field-access lookups are re-used by class/field evaluation paths.
    private val candidateSqlCache = java.util.concurrent.ConcurrentHashMap<String, List<String>>()
    private val localRawDocuments = java.util.HashMap<String, JsonObject>()

    private val annotationOwners = HashMap<String, Set<String>>()

    private val evaluator =
        DexMatcherEvaluator(
            metadata,
            relations,
            ::classUsingString,
            ::methodUsingString,
            ::matchesFieldAnnotations,
            ::selectiveCallersForMethod,
        )

    private fun selectiveCallersForMethod(
        info: DexMethodInfo,
        callerSpecs: List<MethodSpec>,
    ): List<DexMethodInfo>? {
        if (relations !is BridgeMatcherRelations) return null
        if (callerSpecs.isEmpty()) return null
        if (callerSpecs.any { it.callerMethods.isNotEmpty() || !hasSelectiveCallerAnchor(it) }) {
            return null
        }
        val collected = LinkedHashMap<String, DexMethodInfo>()
        for (callerSpec in callerSpecs) {
            val sources = methodCandidateSources(callerSpec, emptyList()) ?: return null
            val descriptors = queryDescriptors(sources)
            if (descriptors.size > 64) return null
            val matched = descriptors.mapNotNull { descriptor ->
                loadMethod(descriptor, callerSpec)?.takeIf { matchesMethodSafely(it, callerSpec) }
            }
            if (matched.isEmpty()) return emptyList()
            for (caller in matched) {
                if (caller.invokes.any { it.descriptor == info.descriptor }) {
                    collected.putIfAbsent(caller.descriptor, caller)
                }
            }
        }
        return collected.values.toList()
    }

    private fun ownersWithAnnotation(sql: String): Set<String> =
        annotationOwners.getOrPut(sql) { query.descriptors(sql).toSet() }

    private fun fieldAnnotationSql(annotations: List<AnnotationSpec>): String {
        require(annotations.size == 1) {
            "Field annotation matching requires one annotation constraint"
        }
        return requireNotNull(annotationOwnerSql("field", annotations.single())) {
            "Field annotation matching requires a type and/or a top-level string value"
        }
    }

    private fun matchesFieldAnnotations(
        descriptor: String,
        annotations: List<AnnotationSpec>,
    ): Boolean = descriptor in ownersWithAnnotation(fieldAnnotationSql(annotations))

    private fun annotationCandidates(
        kind: String,
        annotations: List<AnnotationSpec>,
    ): List<CandidateSource>? {
        val sql = annotations.firstNotNullOfOrNull { annotationOwnerSql(kind, it) } ?: return null
        return listOf(CandidateSource.Descriptors(ownersWithAnnotation(sql).toList()))
    }

    private fun methodUsingString(info: DexMethodInfo, spec: StringSpec): Boolean {
        if (spec.value.isEmpty()) return info.usingStrings.any { spec.matches(it) }
        val methods =
            localStringMethods.getOrPut(spec) {
                val sql = sqlMethod { addMethodStringPredicate(this, spec) }.toSql()
                query.descriptors(sql).toHashSet()
            }
        return info.descriptor in methods
    }

    // Native metadata document construction can fail on obfuscated method refs whose declaring
    // class is an array type (engine limitation, engine repo is frozen). A candidate whose
    // relations cannot be read must be skipped, never abort the whole delegate resolution.
    private fun matchesMethodSafely(info: DexMethodInfo, spec: MethodSpec): Boolean =
        try {
            evaluator.matchesMethod(info, spec)
        } catch (_: DexSqlException) {
            false
        }

    private fun matchesClassSafely(info: DexClassInfo, spec: ClassSpec): Boolean {
        val key = info.descriptor to spec
        classMatchCache[key]?.let {
            return it
        }
        val result =
            try {
                evaluator.matchesClass(info, spec)
            } catch (_: DexSqlException) {
                false
            }
        if (classMatchCache.size < 2048) classMatchCache[key] = result
        return result
    }

    private fun matchesFieldSafely(info: DexFieldInfo, spec: FieldSpec): Boolean =
        try {
            evaluator.matchesField(info, spec)
        } catch (_: DexSqlException) {
            false
        }

    /**
     * Class-level usingStrings evaluation is a set-membership test. The set of classes containing a
     * literal is materialized once by a canonical query (method_strings value -> method descriptors
     * -> declared class descriptors) and cached in the session cache. This turns candidate
     * evaluation from one SQL query per candidate class into one query per distinct literal, then
     * O(1) per class. Nested class specs (declaredClass/returnType/superClass) use the same sets
     * through the evaluator callback.
     */
    private fun classUsingString(info: DexClassInfo, spec: StringSpec): Boolean {
        val descriptor = info.descriptor
        if (dottedClassNameOrNull(descriptor) == null) return false
        return descriptor in classesUsingString(spec)
    }

    private fun classesUsingString(spec: StringSpec): Set<String> {
        val key = spec.match.name + "\u0000" + spec.value
        localStringClasses[key]?.let {
            return it
        }
        sessionCache?.stringClasses(key)?.let {
            localStringClasses[key] = it
            return it
        }
        val classes = computeClassesUsingString(spec)
        localStringClasses[key] = classes
        sessionCache?.cacheStringClasses(key, classes)
        return classes
    }

    private fun computeClassesUsingString(spec: StringSpec): Set<String> {
        val sql =
            try {
                sqlMethod { addMethodStringPredicate(this, spec) }.toSql()
            } catch (_: IllegalArgumentException) {
                return emptySet()
            }
        return try {
            val classes = linkedSetOf<String>()
            query.descriptors(sql).forEach { methodDescriptor ->
                if (!isRealMethodDescriptor(methodDescriptor)) return@forEach
                val declaredClass = declaredClassNameOfMethod(methodDescriptor) ?: return@forEach
                classDescriptorOrNull(declaredClass)?.let { classes += it }
            }
            classes
        } catch (_: DexSqlException) {
            emptySet()
        }
    }

    /** Raw metadata document with session/scope memoization (no repeated native reads). */
    private fun cachedRawDocument(
        key: String,
        kind: DexMetadataKind,
        descriptor: String,
    ): JsonObject? {
        val loader = { rawMetadata?.invoke(kind, descriptor) }
        sessionCache?.let {
            return it.rawDocument(key, loader)
        }
        localRawDocuments[key]?.let {
            return it
        }
        val document = loader() ?: return null
        if (localRawDocuments.size < 2048) localRawDocuments[key] = document
        return document
    }

    fun findMethods(spec: MethodSpec): List<DexMethodInfo> {
        val sources =
            methodCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("method")
        return queryDescriptors(sources)
            .asSequence()
            .filterNot { it.startsWith("[") }
            .filter { methodDescriptorInPackages(it, spec.searchPackages, spec.excludePackages) }
            .mapNotNull { loadMethod(it, spec) }
            .filter { matchesMethodSafely(it, spec) }
            .toList()
    }

    fun findClasses(spec: ClassSpec): List<DexClassInfo> {
        val sources =
            classCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("class")
        val candidates =
            queryDescriptors(sources)
                .asSequence()
                .filterNot { it.startsWith("[") }
                .filter { classDescriptorInPackages(it, spec.searchPackages, spec.excludePackages) }
                .mapNotNull { loadClass(it, spec) }
                .toList()
        preloadClassFieldAccessRelations(candidates, spec)
        return candidates.filter { matchesClassSafely(it, spec) }
    }

    fun findFields(spec: FieldSpec): List<DexFieldInfo> {
        val sources =
            fieldCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("field")
        val candidates =
            queryDescriptors(sources)
                .asSequence()
                .filterNot { it.startsWith("[") }
                .filter { fieldDescriptorInPackages(it, spec.searchPackages, spec.excludePackages) }
                .toList()
        preloadFieldAccessRelations(candidates, spec)
        return candidates
            .asSequence()
            .mapNotNull { loadField(it, spec) }
            .filter { matchesFieldSafely(it, spec) }
            .toList()
    }

    /**
     * Single-result helper: null when nothing matched; multiple matches are an ambiguity error.
     * Evaluation stops as soon as a second match is found; candidates are paged.
     */
    fun uniqueMethod(spec: MethodSpec): String? =
        uniqueMatches(findMethodsUpToTwo(spec), "method") {
            it.descriptor
        }

    /** Single-result helper: null when nothing matched; multiple matches are an ambiguity error. */
    fun uniqueClass(spec: ClassSpec): String? =
        uniqueMatches(findClassesUpToTwo(spec), "class") {
            it.descriptor
        }

    /** Single-result helper: null when nothing matched; multiple matches are an ambiguity error. */
    fun uniqueField(spec: FieldSpec): String? =
        uniqueMatches(findFieldsUpToTwo(spec), "field") {
            it.descriptor
        }

    // ---------------------------------------------------------------------
    // Bounded unique search (stop at the second match, paged candidates)
    // ---------------------------------------------------------------------

    private fun findMethodsUpToTwo(spec: MethodSpec): List<DexMethodInfo> {
        val sources =
            methodCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("method")
        val matches = mutableListOf<DexMethodInfo>()
        val matchedDescriptors = HashSet<String>(4)
        forEachCandidateDescriptor(sources) { descriptor ->
            if (
                !descriptor.startsWith("[") &&
                    methodDescriptorInPackages(
                        descriptor,
                        spec.searchPackages,
                        spec.excludePackages,
                    )
            ) {
                val info = loadMethod(descriptor, spec)
                if (
                    info != null &&
                        matchesMethodSafely(info, spec) &&
                        matchedDescriptors.add(info.descriptor)
                ) {
                    matches += info
                }
            }
            matches.size >= 2
        }
        return matches
    }

    private fun findClassesUpToTwo(spec: ClassSpec): List<DexClassInfo> {
        val sources =
            classCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("class")
        val matches = mutableListOf<DexClassInfo>()
        val matchedDescriptors = HashSet<String>(4)
        forEachCandidateDescriptor(sources) { descriptor ->
            if (
                !descriptor.startsWith("[") &&
                    classDescriptorInPackages(descriptor, spec.searchPackages, spec.excludePackages)
            ) {
                val info = loadClass(descriptor, spec)
                if (
                    info != null &&
                        matchesClassSafely(info, spec) &&
                        matchedDescriptors.add(info.descriptor)
                ) {
                    matches += info
                }
            }
            matches.size >= 2
        }
        return matches
    }

    private fun findFieldsUpToTwo(spec: FieldSpec): List<DexFieldInfo> {
        val sources =
            fieldCandidateSources(spec, spec.searchPackages) ?: unsupportedCandidate("field")
        val candidates =
            queryDescriptors(sources)
                .asSequence()
                .filterNot { it.startsWith("[") }
                .filter { fieldDescriptorInPackages(it, spec.searchPackages, spec.excludePackages) }
                .toList()
        preloadFieldAccessRelations(candidates, spec)
        val matches = mutableListOf<DexFieldInfo>()
        val matchedDescriptors = HashSet<String>(4)
        for (descriptor in candidates) {
            val info = loadField(descriptor, spec)
            if (
                info != null &&
                    matchesFieldSafely(info, spec) &&
                    matchedDescriptors.add(info.descriptor)
            ) {
                matches += info
            }
            if (matches.size >= 2) break
        }
        return matches
    }

    private fun forEachCandidateDescriptor(
        sources: List<CandidateSource>,
        action: (String) -> Boolean,
    ) {
        for (source in sources) {
            when (source) {
                is CandidateSource.Descriptors -> {
                    for (descriptor in source.descriptors) {
                        if (action(descriptor)) return
                    }
                }

                is CandidateSource.Sql -> {
                    var offset = 0
                    while (true) {
                        val pageSql = pagedSql(source.sql, candidatePageSize, offset)
                        val page =
                            sessionCache?.candidateRows(pageSql) { query.descriptors(pageSql) }
                                ?: query.descriptors(pageSql)
                        if (page.isEmpty()) break
                        for (descriptor in page) {
                            if (action(descriptor)) return
                        }
                        if (page.size < candidatePageSize) break
                        offset += candidatePageSize
                    }
                }
            }
        }
    }

    private fun queryDescriptors(sources: List<CandidateSource>): List<String> =
        sources
            .flatMap { source ->
                when (source) {
                    is CandidateSource.Descriptors -> {
                        source.descriptors
                    }

                    is CandidateSource.Sql -> {
                        sessionCache?.candidateRows(source.sql) {
                            query.descriptors(source.sql)
                        }
                            ?: candidateSqlCache[source.sql]
                            ?: run {
                                val rows = query.descriptors(source.sql)
                                // Only cache small candidate sets: a huge scan list must not be
                                // retained.
                                if (rows.size <= DEFAULT_CANDIDATE_PAGE_SIZE) {
                                    candidateSqlCache[source.sql] = rows
                                }
                                rows
                            }
                    }
                }
            }
            .distinct()

    private fun <T> uniqueMatches(
        matches: List<T>,
        kind: String,
        descriptor: (T) -> String,
    ): String? =
        when (matches.size) {
            0 -> {
                null
            }

            1 -> {
                descriptor(matches.single())
            }

            else -> {
                error(
                    "Query matcher: multiple " +
                        kind +
                        "s matched, expected one: " +
                        matches.joinToString(",") { descriptor(it) },
                )
            }
        }

    // ---------------------------------------------------------------------
    // Candidate loading with cheap scalar prefiltering
    // ---------------------------------------------------------------------

    private fun loadMethod(descriptor: String, spec: MethodSpec): DexMethodInfo? {
        // Candidate SQL/descriptor shortcuts must never feed array/primitive class descriptors or
        // malformed members into the native metadata API.
        if (!isRealMethodDescriptor(descriptor)) return null
        if (rawMetadata == null) {
            return try {
                metadata.methodInfo(descriptor)
            } catch (_: DexSqlException) {
                null
            }
        }
        val json =
            try {
                cachedRawDocument("method|$descriptor", DexMetadataKind.Method, descriptor)
                    ?: return null
            } catch (_: DexSqlException) {
                return null
            }
        if (!methodPrefilter(json, spec)) return null
        return DexMethodInfo(json, metadata)
    }

    private fun loadClass(descriptor: String, spec: ClassSpec): DexClassInfo? {
        // Class candidates must be object class descriptors; array/primitive descriptors have no
        // dataset class metadata and must never reach the native API.
        if (classDescriptorOrNull(descriptor) == null) return null
        if (rawMetadata == null) {
            return try {
                metadata.classInfo(descriptor)
            } catch (_: DexSqlException) {
                null
            }
        }
        val json =
            try {
                cachedRawDocument("class|$descriptor", DexMetadataKind.Class, descriptor)
                    ?: return null
            } catch (_: DexSqlException) {
                return null
            }
        if (!classPrefilter(json, spec)) return null
        return DexClassInfo(json, metadata)
    }

    private fun loadField(descriptor: String, spec: FieldSpec): DexFieldInfo? {
        if (!isRealFieldDescriptor(descriptor)) return null
        if (rawMetadata == null) {
            return try {
                metadata.fieldInfo(descriptor)
            } catch (_: DexSqlException) {
                null
            }
        }
        val json =
            try {
                cachedRawDocument("field|$descriptor", DexMetadataKind.Field, descriptor)
                    ?: return null
            } catch (_: DexSqlException) {
                return null
            }
        if (!fieldPrefilter(json, spec)) return null
        return DexFieldInfo(json, metadata)
    }

    // ---------------------------------------------------------------------
    // Candidate source generation: canonical fast-path shapes only
    // ---------------------------------------------------------------------

    private fun methodCandidateSources(
        spec: MethodSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        // Exact descriptor specs need no SQL: the descriptor itself is the only candidate.
        spec.descriptor?.let {
            return listOf(CandidateSource.Descriptors(listOf(it)))
        }
        methodOwnCandidateSources(spec, searchPackages)?.let {
            return it
        }
        for (child in spec.allOf) {
            methodOwnCandidateSources(child, emptyList())?.let {
                return it
            }
        }
        if (spec.anyOf.isNotEmpty()) {
            val childSources = spec.anyOf.map { methodOwnCandidateSources(it, emptyList()) }
            if (childSources.all { it != null }) {
                return childSources.filterNotNull().flatten().distinct()
            }
        }
        return null
    }

    private fun methodOwnCandidateSources(
        spec: MethodSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        annotationCandidates("method", spec.annotations)?.let {
            return it
        }
        val allPackages = (searchPackages + spec.searchPackages).distinct()
        val resolvedReturnTypes = resolveEmptyOrSingleReturnTypeConstraint(spec)
        if (resolvedReturnTypes != null && resolvedReturnTypes.isEmpty()) {
            return listOf(CandidateSource.Descriptors(emptyList()))
        }
        val resolvedReturnType = resolvedReturnTypes?.singleOrNull()
        if (!hasStrongOwnMethodAnchor(spec)) {
            declaredClassStructuralMethodSources(spec, allPackages)?.let {
                return it
            }
            selectiveInvokeMethodSources(spec, allPackages)?.let {
                return it
            }
            selectiveUsingFieldMethodSources(spec, allPackages)?.let {
                return it
            }
        }
        val steps = methodCandidateSteps(spec, searchPackages, resolvedReturnType)
        if (steps != null) {
            return listOf(
                CandidateSource.Sql(sqlMethod { steps.forEach { step -> step(this) } }.toSql()),
            )
        }
        return selectiveCallerMethodSources(spec, allPackages)
    }

    private fun hasStrongOwnMethodAnchor(spec: MethodSpec): Boolean {
        if (spec.descriptor != null) return true
        if (spec.usingStrings.any { it.value.isNotEmpty() }) return true
        if (spec.usingNumbers.isNotEmpty()) return true
        val dc = spec.declaredClass
        if (dc != null) {
            if (dc.className?.match == NameMatch.Equals) return true
            if (dc.usingStrings.any { it.value.isNotEmpty() }) return true
            if (dc.usingNumbers.isNotEmpty()) return true
        }
        val name = spec.name
        if (
            name != null &&
                name.match == NameMatch.Equals &&
                name.value != "<init>" &&
                name.value != "<clinit>"
        ) {
            return true
        }
        val paramTypes = spec.paramTypes
        if (paramTypes != null) {
            val hasNarrowParam = paramTypes.any { type ->
                type != null &&
                    type.match == NameMatch.Equals &&
                    dottedClassNameOrNull(type.value)?.let { dotted ->
                        dotted !in BROAD_FIELD_TYPE_NAMES && !isBroadPackageType(dotted)
                    } == true
            }
            if (hasNarrowParam) return true
        }
        return false
    }

    private fun declaredClassStructuralMethodSources(
        spec: MethodSpec,
        allPackages: List<String>,
    ): List<CandidateSource>? {
        val dc = spec.declaredClass ?: return null
        val hasStructural =
            dc.superClass != null ||
                dc.annotations.isNotEmpty() ||
                dc.interfaces.isNotEmpty() ||
                dc.fields.isNotEmpty() ||
                dc.methods.isNotEmpty() ||
                dc.fieldCount != null ||
                dc.methodCount != null
        if (!hasStructural) return null
        val ownerSources = classCandidateSources(dc, allPackages) ?: return null
        val owners =
            queryDescriptors(ownerSources).filter {
                classDescriptorInPackages(it, allPackages, spec.excludePackages)
            }
        if (owners.isEmpty()) return listOf(CandidateSource.Descriptors(emptyList()))
        if (owners.size > 32) return null
        val methodDescs = linkedSetOf<String>()
        for (ownerDesc in owners) {
            val cls = loadClass(ownerDesc, dc) ?: continue
            if (!matchesClassSafely(cls, dc)) continue
            for (method in cls.methods) {
                val desc = method.descriptor
                if (!isRealMethodDescriptor(desc)) continue
                if (!methodDescriptorInPackages(desc, allPackages, spec.excludePackages)) continue
                if (spec.name?.matches(method.name) == false) continue
                if (spec.paramCount != null && method.paramCount !in spec.paramCount) continue
                if (
                    spec.modifiers != null &&
                        (method.modifiers and spec.modifiers) != spec.modifiers
                ) {
                    continue
                }
                methodDescs += desc
            }
        }
        return listOf(CandidateSource.Descriptors(methodDescs.toList()))
    }

    private fun selectiveInvokeMethodSources(
        spec: MethodSpec,
        allPackages: List<String>,
    ): List<CandidateSource>? {
        for (invSpec in spec.invokeMethods) {
            val callers =
                when {
                    invSpec.descriptor != null -> {
                        val sql =
                            "SELECT DISTINCT mc.method AS method FROM method_calls mc " +
                                "WHERE mc.callee = " +
                                sqlQuote(invSpec.descriptor) +
                                " ORDER BY mc.method;"
                        queryDescriptors(listOf(CandidateSource.Sql(sql)))
                    }

                    isDirectSelectiveCalleeClassSpec(invSpec) -> {
                        val calleeClass =
                            classDescriptorOrNull(invSpec.declaredClass!!.className!!.value)
                                ?: continue
                        val nameClause =
                            invSpec.name
                                ?.takeIf { it.match == NameMatch.Equals }
                                ?.let { " AND mc.callee_name = ${sqlQuote(it.value)}" } ?: ""
                        val sql =
                            "SELECT DISTINCT mc.method AS method FROM method_calls mc " +
                                "WHERE mc.callee_class = " +
                                sqlQuote(calleeClass) +
                                nameClause +
                                " ORDER BY mc.method;"
                        queryDescriptors(listOf(CandidateSource.Sql(sql)))
                    }

                    isSelectiveInvokeMethodAnchor(invSpec) -> {
                        val calleeSources = methodCandidateSources(invSpec, emptyList()) ?: continue
                        val calleeDescs = queryDescriptors(calleeSources)
                        if (calleeDescs.isEmpty())
                            return listOf(CandidateSource.Descriptors(emptyList()))
                        if (calleeDescs.size > 16) continue
                        val matchedCallers = linkedSetOf<String>()
                        for (calleeDesc in calleeDescs) {
                            if (!isRealMethodDescriptor(calleeDesc)) continue
                            val sql =
                                "SELECT DISTINCT mc.method AS method FROM method_calls mc " +
                                    "WHERE mc.callee = " +
                                    sqlQuote(calleeDesc) +
                                    " ORDER BY mc.method;"
                            matchedCallers += queryDescriptors(listOf(CandidateSource.Sql(sql)))
                        }
                        matchedCallers.toList()
                    }

                    else -> {
                        null
                    }
                } ?: continue
            val filtered =
                callers
                    .filter {
                        isRealMethodDescriptor(it) &&
                            methodDescriptorInPackages(it, allPackages, spec.excludePackages)
                    }
                    .distinct()
            return listOf(CandidateSource.Descriptors(filtered))
        }
        return null
    }

    private fun selectiveUsingFieldMethodSources(
        spec: MethodSpec,
        allPackages: List<String>,
    ): List<CandidateSource>? {
        for (uf in spec.usingFields) {
            if (!isSelectiveUsingFieldSpec(uf.field)) continue
            val fieldSources = fieldCandidateSources(uf.field, emptyList()) ?: continue
            val fieldDescs = queryDescriptors(fieldSources)
            if (fieldDescs.isEmpty()) return listOf(CandidateSource.Descriptors(emptyList()))
            if (fieldDescs.size > 8) continue
            val usingClause =
                when (uf.usingType) {
                    dev.ujhhgtg.dexsql.meta.FieldUsingType.Read -> " AND fa0.using_type = 'get'"
                    dev.ujhhgtg.dexsql.meta.FieldUsingType.Write -> " AND fa0.using_type = 'put'"
                    null -> ""
                }
            val callers = linkedSetOf<String>()
            for (fieldDesc in fieldDescs) {
                if (!isRealFieldDescriptor(fieldDesc)) continue
                val sql =
                    "SELECT DISTINCT fa0.method AS method FROM method_field_accesses fa0 " +
                        "WHERE fa0.field = " +
                        sqlQuote(fieldDesc) +
                        usingClause +
                        " ORDER BY fa0.method;"
                callers += queryDescriptors(listOf(CandidateSource.Sql(sql)))
            }
            val filtered =
                callers
                    .filter {
                        isRealMethodDescriptor(it) &&
                            methodDescriptorInPackages(it, allPackages, spec.excludePackages)
                    }
                    .distinct()
            return listOf(CandidateSource.Descriptors(filtered))
        }
        return null
    }

    private fun selectiveCallerMethodSources(
        spec: MethodSpec,
        allPackages: List<String>,
    ): List<CandidateSource>? {
        val callerSpec =
            spec.callerMethods.firstOrNull {
                it.callerMethods.isEmpty() && hasSelectiveCallerAnchor(it)
            } ?: return null
        val callers = findMethods(callerSpec)
        if (callers.isEmpty()) return listOf(CandidateSource.Descriptors(emptyList()))
        val callees =
            callers
                .flatMap { caller -> caller.invokes.map { it.descriptor } }
                .filter {
                    isRealMethodDescriptor(it) &&
                        methodDescriptorInPackages(it, allPackages, spec.excludePackages)
                }
                .distinct()
        return listOf(CandidateSource.Descriptors(callees))
    }

    private fun resolveEmptyOrSingleReturnTypeConstraint(spec: MethodSpec): List<String>? {
        val rt = spec.returnType ?: return null
        if (rt.className != null) return null
        val selective =
            rt.usingStrings.any { it.value.isNotEmpty() } ||
                rt.usingNumbers.isNotEmpty() ||
                rt.annotations.isNotEmpty() ||
                rt.superClass != null
        if (!selective) return null
        val sources = classCandidateSources(rt, emptyList()) ?: return null
        val descs = queryDescriptors(sources)
        return if (descs.size <= 4) descs else null
    }

    private fun isDirectSelectiveCalleeClassSpec(invSpec: MethodSpec): Boolean {
        val classNameSpec = invSpec.declaredClass?.className ?: return false
        if (classNameSpec.match != NameMatch.Equals) return false
        val dotted = dottedClassNameOrNull(classNameSpec.value) ?: return false
        if (dotted in BROAD_FIELD_TYPE_NAMES || isBroadPackageType(dotted)) return false
        return invSpec.usingStrings.none { it.value.isNotEmpty() } &&
            invSpec.usingNumbers.isEmpty() &&
            invSpec.annotations.isEmpty() &&
            invSpec.returnType == null &&
            invSpec.paramTypes == null &&
            invSpec.paramCount == null &&
            invSpec.modifiers == null &&
            invSpec.invokeMethods.isEmpty() &&
            invSpec.callerMethods.isEmpty() &&
            invSpec.usingFields.isEmpty()
    }

    private fun isSelectiveInvokeMethodAnchor(invSpec: MethodSpec): Boolean =
        invSpec.descriptor != null ||
            invSpec.usingStrings.any { it.value.isNotEmpty() } ||
            invSpec.usingNumbers.isNotEmpty() ||
            invSpec.annotations.isNotEmpty() ||
            (invSpec.declaredClass?.className?.match == NameMatch.Equals &&
                dottedClassNameOrNull(invSpec.declaredClass.className.value)?.let {
                    it !in BROAD_FIELD_TYPE_NAMES && !isBroadPackageType(it)
                } == true)

    private fun isSelectiveUsingFieldSpec(fieldSpec: FieldSpec): Boolean =
        (fieldSpec.name?.match == NameMatch.Equals && fieldSpec.name.value.length >= 4) ||
            (fieldSpec.declaredClass?.className?.match == NameMatch.Equals &&
                dottedClassNameOrNull(fieldSpec.declaredClass.className.value)?.let {
                    it !in BROAD_FIELD_TYPE_NAMES && !isBroadPackageType(it)
                } == true) ||
            typeOnlyFieldIsNarrow(fieldSpec)

    private fun hasSelectiveCallerAnchor(spec: MethodSpec): Boolean =
        spec.descriptor != null ||
            spec.usingStrings.any { it.value.isNotEmpty() } ||
            spec.usingNumbers.isNotEmpty() ||
            spec.annotations.isNotEmpty() ||
            spec.declaredClass?.className?.match == NameMatch.Equals ||
            spec.declaredClass?.usingStrings?.any { it.value.isNotEmpty() } == true ||
            spec.declaredClass?.usingNumbers?.isNotEmpty() == true

    private fun isBroadPackageType(javaName: String): Boolean =
        BROAD_FIELD_TYPE_PREFIXES.any { prefix ->
            javaName.startsWith(prefix)
        }

    /**
     * Canonical, pushable method predicates of one MethodSpec. Returns null when the spec has no
     * fast-path-expressible predicate (array/primitive returnType non-equals modes and empty string
     * literals are deliberately evaluated in Kotlin only).
     */
    private fun methodCandidateSteps(
        spec: MethodSpec,
        searchPackages: List<String>,
        resolvedReturnTypeDescriptor: String? =
            resolveEmptyOrSingleReturnTypeConstraint(spec)?.singleOrNull(),
    ): List<(SqlMethodQuery) -> Unit>? {
        val steps = mutableListOf<(SqlMethodQuery) -> Unit>()
        spec.descriptor?.let { descriptor -> steps += { query -> query.descriptor = descriptor } }
        spec.name
            ?.takeIf { it.match == NameMatch.Equals }
            ?.let { nameSpec ->
                steps += { q -> q.name = nameSpec.value }
            }
        spec.modifiers?.let { mask -> steps += { q -> q.modifiers(mask) } }
        spec.declaredClass?.let { classSpec ->
            classSpec.className?.let { nameSpec ->
                // Class names must be object class names; primitive/array values cannot match any
                // real class and must not be converted to malformed "L...[];" descriptors.
                dottedClassNameOrNull(nameSpec.value)?.let { dotted ->
                    steps += { q -> q.className(nameSpec.match.toSqlMode(), dotted) }
                }
            }
            if (classSpec.searchPackages.isNotEmpty()) {
                val classPackages = classSpec.searchPackages.toTypedArray()
                steps += { q -> q.searchPackages(*classPackages) }
            }
            val nestedClassStrings =
                classSpec.methods.flatMap { it.usingStrings }.filter { it.value.isNotEmpty() }
            val nestedClassNumbers = classSpec.methods.flatMap { it.usingNumbers }
            val classLiterals = (classSpec.usingStrings + nestedClassStrings).distinct()
            val classNumbers = (classSpec.usingNumbers + nestedClassNumbers).distinct()
            if (classLiterals.isNotEmpty() || classNumbers.isNotEmpty()) {
                val numbers = classNumbers.map { it as Any }.toTypedArray()
                steps += { q ->
                    q.declaredClass {
                        addClassLiteralStrings(classLiterals)
                        if (numbers.isNotEmpty()) usingNumbers(*numbers)
                    }
                }
            }
        }
        spec.returnType
            ?.className
            ?.takeIf { it.match != NameMatch.EndsWith }
            ?.let { nameSpec ->
                val javaName = javaTypeNameOf(nameSpec.value)
                if (javaName.isNotEmpty()) {
                    if (nameSpec.match == NameMatch.Equals) {
                        steps += { q -> q.returnType(SqlStringMatchMode.Equals, javaName) }
                    } else if (!isPrimitiveOrArrayTypeName(javaName)) {
                        // Non-equals class-name modes require a dotted class name; array/primitive
                        // values are evaluated in Kotlin only.
                        steps += { q -> q.returnType(nameSpec.match.toSqlMode(), javaName) }
                    }
                }
            }
        resolvedReturnTypeDescriptor?.let(::descriptorToJavaName)?.let { javaName ->
            steps += { q -> q.returnType(SqlStringMatchMode.Equals, javaName) }
        }
        spec.paramCount?.let { range -> steps += { q -> q.paramCount(range.first, range.last) } }
        spec.opcodes?.count?.let { range -> steps += { q -> q.opcodeCount(range) } }
        spec.paramTypes
            ?.takeIf { types -> types.all { it == null || it.match == NameMatch.Equals } }
            ?.let { types ->
                val values = types.map { type -> type?.value?.let(::javaTypeNameOf) }.toTypedArray()
                steps += { q -> q.paramTypes(*values) }
            }
        // Empty literals are Kotlin-only existential semantics (DexKit usingEqStrings(""));
        // emitting
        // them as SQL would create a broad method_strings predicate that steals candidate priority
        // from narrower sources (e.g. a package-only class scan). Non-empty literals stay
        // canonical.
        spec.usingStrings
            .filter { it.value.isNotEmpty() }
            .forEach { stringSpec ->
                steps += { q -> addMethodStringPredicate(q, stringSpec) }
            }
        if (spec.usingNumbers.isNotEmpty()) {
            val numbers = spec.usingNumbers.map { it as Any }.toTypedArray()
            steps += { q -> q.usingNumbers(*numbers) }
        }
        val allPackages = (searchPackages + spec.searchPackages).distinct()
        if (allPackages.isNotEmpty()) {
            val pack = allPackages.toTypedArray()
            steps += { q -> q.searchPackages(*pack) }
        }
        return steps.ifEmpty { null }
    }

    private fun classCandidateSources(
        spec: ClassSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        val scopePackages = (searchPackages + spec.searchPackages).distinct()
        // 1) Annotation & explicit class name (canonical class scan).
        annotationCandidates("class", spec.annotations)?.let {
            return it
        }
        classDirectCandidateSources(spec, scopePackages)?.let {
            return it
        }
        // 2) Class-level usingStrings: canonical method lookup for each non-empty literal.
        val nonEmptyClassStrings = spec.usingStrings.filter { it.value.isNotEmpty() }
        if (nonEmptyClassStrings.isNotEmpty()) {
            var classDescriptors: LinkedHashSet<String>? = null
            for (stringSpec in nonEmptyClassStrings) {
                val literalClasses = classesUsingString(stringSpec)
                classDescriptors =
                    if (classDescriptors == null) {
                        literalClasses.filterTo(LinkedHashSet()) {
                            classDescriptorInPackages(it, scopePackages, spec.excludePackages)
                        }
                    } else {
                        classDescriptors.apply { retainAll(literalClasses) }
                    }
                if (classDescriptors.isEmpty()) break
            }
            val result =
                intersectLargeClassCandidates(
                    spec,
                    scopePackages,
                    classDescriptors ?: LinkedHashSet(),
                )
            return listOf(CandidateSource.Descriptors(result.toList()))
        }
        // 3) Nested member methods: rank pushable units by selectivity, drive from the most
        //    selective one, and intersect further units + fields/superclass while still large.
        if (spec.methods.isNotEmpty()) {
            val rankedMethods =
                spec.methods
                    .map { methodSpec -> methodUnitSelectivity(methodSpec) to methodSpec }
                    .filter { (score, _) -> score > 0 }
                    .sortedByDescending { (score, _) -> score }
            if (rankedMethods.isNotEmpty()) {
                var candidates: LinkedHashSet<String>? = null
                for ((_, methodSpec) in rankedMethods) {
                    val methodSources =
                        methodCandidateSources(methodSpec, scopePackages) ?: continue
                    val unitClasses = classDescriptorsOfMethodSources(methodSources)
                    candidates =
                        if (candidates == null) {
                            unitClasses.filterTo(LinkedHashSet()) {
                                classDescriptorInPackages(it, scopePackages, spec.excludePackages)
                            }
                        } else {
                            candidates.apply { retainAll(unitClasses) }
                        }
                    if (
                        candidates.isEmpty() ||
                            candidates.size <= NESTED_CANDIDATE_INTERSECTION_THRESHOLD
                    ) {
                        break
                    }
                }
                if (candidates != null) {
                    candidates = intersectFieldCount(spec, candidates, scopePackages)
                    if (
                        candidates.size > NESTED_CANDIDATE_INTERSECTION_THRESHOLD &&
                            spec.fields.isNotEmpty()
                    ) {
                        val rankedFields =
                            spec.fields
                                .map { fieldSpec -> fieldUnitSelectivity(fieldSpec) to fieldSpec }
                                .filter { (score, _) -> score > 0 }
                                .sortedByDescending { (score, _) -> score }
                        for ((_, fieldSpec) in rankedFields) {
                            val fieldSources =
                                fieldCandidateSources(fieldSpec, scopePackages) ?: continue
                            val unitClasses = classDescriptorsOfFieldSources(fieldSources)
                            candidates.retainAll(unitClasses)
                            if (
                                candidates.isEmpty() ||
                                    candidates.size <= NESTED_CANDIDATE_INTERSECTION_THRESHOLD
                            ) {
                                break
                            }
                        }
                    }
                    candidates = intersectLargeClassCandidates(spec, scopePackages, candidates)
                    return listOf(CandidateSource.Descriptors(candidates.toList()))
                }
            }
        }
        // 4) Nested member fields: rank by selectivity and intersect while still large.
        if (spec.fields.isNotEmpty()) {
            val rankedFields =
                spec.fields
                    .map { fieldSpec -> fieldUnitSelectivity(fieldSpec) to fieldSpec }
                    .filter { (score, _) -> score > 0 }
                    .sortedByDescending { (score, _) -> score }
            if (rankedFields.isNotEmpty()) {
                var candidates: LinkedHashSet<String>? = null
                for ((_, fieldSpec) in rankedFields) {
                    val fieldSources = fieldCandidateSources(fieldSpec, scopePackages) ?: continue
                    val unitClasses = classDescriptorsOfFieldSources(fieldSources)
                    candidates =
                        if (candidates == null) {
                            unitClasses.filterTo(LinkedHashSet()) {
                                classDescriptorInPackages(it, scopePackages, spec.excludePackages)
                            }
                        } else {
                            candidates.apply { retainAll(unitClasses) }
                        }
                    if (
                        candidates.isEmpty() ||
                            candidates.size <= NESTED_CANDIDATE_INTERSECTION_THRESHOLD
                    ) {
                        break
                    }
                }
                if (candidates != null) {
                    candidates = intersectFieldCount(spec, candidates, scopePackages)
                    candidates = intersectLargeClassCandidates(spec, scopePackages, candidates)
                    return listOf(CandidateSource.Descriptors(candidates.toList()))
                }
            }
        }
        // 5) Class-level numeric-operand units.
        if (spec.usingNumbers.isNotEmpty()) {
            val numbers = spec.usingNumbers.map { it as Any }
            val sql = sqlClass {
                numbers.forEach { usingNumbers(it) }
                appendClassScalarConstraints(this, spec, scopePackages, includeSuperClass = false)
            }
                .toSql()
            return listOf(CandidateSource.Sql(sql))
        }
        // 6) Superclass-only or superclass-anchored class specs.
        spec.superClass?.className?.let { nameSpec ->
            if (dottedClassNameOrNull(nameSpec.value) != null) {
                val sql = sqlClass {
                    appendClassScalarConstraints(
                        this,
                        spec,
                        scopePackages,
                        includeSuperClass = true,
                    )
                }
                    .toSql()
                return listOf(CandidateSource.Sql(sql))
            }
        }
        // 7) Canonical class access-flag scan.
        spec.modifiers?.let {
            val sql = sqlClass {
                appendClassScalarConstraints(this, spec, scopePackages, includeSuperClass = true)
            }
                .toSql()
            return listOf(CandidateSource.Sql(sql))
        }
        // 8) Field count constraint.
        spec.fieldCount?.let { range ->
            if (
                spec.methodCount == null &&
                    spec.interfaceCount == null &&
                    spec.excludePackages.isEmpty() &&
                    spec.superClass?.className == null &&
                    spec.modifiers == null
            ) {
                return listOf(CandidateSource.Sql(classFieldCountSql(range, scopePackages)))
            }
            val sql = sqlClass {
                appendClassScalarConstraints(this, spec, scopePackages, includeSuperClass = true)
            }
                .toSql()
            return listOf(CandidateSource.Sql(sql))
        }
        // 9) Package-only canonical class scan.
        if (scopePackages.isNotEmpty()) {
            val sql = sqlClass {
                appendClassScalarConstraints(this, spec, scopePackages, includeSuperClass = true)
            }
                .toSql()
            return listOf(CandidateSource.Sql(sql))
        }
        return null
    }

    private fun intersectLargeClassCandidates(
        spec: ClassSpec,
        scopePackages: List<String>,
        candidates: LinkedHashSet<String>,
    ): LinkedHashSet<String> {
        if (candidates.size <= NESTED_CANDIDATE_INTERSECTION_THRESHOLD) return candidates
        val hasSuperClass =
            spec.superClass?.className?.let { dottedClassNameOrNull(it.value) } != null
        val hasScalar =
            hasSuperClass ||
                spec.modifiers != null ||
                spec.methodCount != null ||
                spec.interfaceCount != null ||
                spec.fieldCount != null
        if (!hasScalar) return candidates
        val sql = sqlClass {
            appendClassScalarConstraints(this, spec, scopePackages, includeSuperClass = true)
        }
            .toSql()
        val allowed = queryDescriptors(listOf(CandidateSource.Sql(sql))).toHashSet()
        return candidates.filterTo(LinkedHashSet()) { it in allowed }
    }

    private fun appendClassScalarConstraints(
        query: SqlClassQuery,
        spec: ClassSpec,
        scopePackages: List<String>,
        includeSuperClass: Boolean,
    ) {
        if (includeSuperClass) {
            spec.superClass?.className?.let { nameSpec ->
                dottedClassNameOrNull(nameSpec.value)?.let { dotted ->
                    query.superClass(nameSpec.match.toSqlMode(), dotted)
                }
            }
        }
        spec.modifiers?.let { query.modifiers = it }
        spec.fieldCount?.let(query::fieldCount)
        spec.methodCount?.let(query::methodCount)
        spec.interfaceCount?.let(query::interfaceCount)
        if (scopePackages.isNotEmpty()) query.searchPackages(*scopePackages.toTypedArray())
        if (spec.excludePackages.isNotEmpty())
            query.excludePackages(*spec.excludePackages.toTypedArray())
    }

    /** Class descriptors of the methods matched by a canonical method candidate source. */
    private fun classDescriptorsOfMethodSources(
        sources: List<CandidateSource>,
    ): LinkedHashSet<String> {
        val classes = linkedSetOf<String>()
        queryDescriptors(sources).forEach { methodDescriptor ->
            if (!isRealMethodDescriptor(methodDescriptor)) return@forEach
            val declaredClass = declaredClassNameOfMethod(methodDescriptor) ?: return@forEach
            classDescriptorOrNull(declaredClass)?.let { classes += it }
        }
        return classes
    }

    /** Class descriptors of the fields matched by a canonical field candidate source. */
    private fun classDescriptorsOfFieldSources(
        sources: List<CandidateSource>,
    ): LinkedHashSet<String> {
        val classes = linkedSetOf<String>()
        queryDescriptors(sources).forEach { fieldDescriptor ->
            if (!isRealFieldDescriptor(fieldDescriptor)) return@forEach
            val declaredClass = declaredClassNameOfField(fieldDescriptor) ?: return@forEach
            classDescriptorOrNull(declaredClass)?.let { classes += it }
        }
        return classes
    }

    /**
     * Selectivity rank for a nested member method used as a class-candidate unit. Pushable
     * predicates rank exact paramTypes > paramCount > returnType > modifiers > declaredClass >
     * usingStrings > non-constructor name; opcodes/annotations and constructor names are
     * deliberately non-selective (score 0).
     */
    private fun methodUnitSelectivity(spec: MethodSpec): Int {
        var score = 0
        if (spec.annotations.isNotEmpty()) score = maxOf(score, 120)
        if (spec.usingStrings.any { it.value.isNotEmpty() }) score = maxOf(score, 115)
        if (spec.invokeMethods.any(::isSelectiveInvokeMethodAnchor)) score = maxOf(score, 108)
        if (spec.usingNumbers.isNotEmpty()) score = maxOf(score, 105)
        val returnTypeSpec = spec.returnType
        if (
            returnTypeSpec != null &&
                returnTypeSpec.className == null &&
                (returnTypeSpec.usingStrings.any { it.value.isNotEmpty() } ||
                    returnTypeSpec.usingNumbers.isNotEmpty() ||
                    returnTypeSpec.superClass != null)
        ) {
            score = maxOf(score, 102)
        }
        val paramTypes = spec.paramTypes
        if (
            paramTypes != null &&
                paramTypes.all { type -> type == null || type.match == NameMatch.Equals }
        ) {
            score = maxOf(score, 100)
        }
        if (spec.paramCount != null) score = maxOf(score, 80)
        val returnTypeName = spec.returnType?.className
        if (returnTypeName != null && returnTypeName.match != NameMatch.EndsWith) {
            score = maxOf(score, 60)
        }
        if (spec.modifiers != null) score = maxOf(score, 50)
        if (
            spec.declaredClass?.className?.let { dottedClassNameOrNull(it.value) } != null ||
                spec.declaredClass?.usingStrings?.any { it.value.isNotEmpty() } == true
        ) {
            score = maxOf(score, 40)
        }
        if (spec.searchPackages.isNotEmpty()) score = maxOf(score, 22)
        val name = spec.name
        if (
            name != null &&
                name.match == NameMatch.Equals &&
                name.value != "<init>" &&
                name.value != "<clinit>"
        ) {
            score = maxOf(score, 20)
        }
        return score
    }

    /**
     * Selectivity rank for a nested member field used as a class-candidate unit. Named fields >
     * declaring class > narrow type > selective read/write accessors; broad type-only fields and
     * count-only constraints are non-selective (score 0).
     */
    private fun fieldUnitSelectivity(spec: FieldSpec): Int {
        var score = 0
        if (spec.annotations.isNotEmpty()) score = 110
        if (spec.name?.match == NameMatch.Equals) score = maxOf(score, 100)
        spec.declaredClass
            ?.takeIf(::classSpecIsNameOnly)
            ?.className
            ?.takeIf { it.match == NameMatch.Equals && dottedClassNameOrNull(it.value) != null }
            ?.let { score = maxOf(score, 80) }
        if (typeOnlyFieldIsNarrow(spec)) score = maxOf(score, 60)
        if ((spec.readMethods + spec.writeMethods).any(::methodSpecIsSelectiveForAccessUnit)) {
            score = maxOf(score, 40)
        }
        return score
    }

    /**
     * True when a name-less field type matcher is narrow enough to drive a class candidate.
     *
     * Accepted: name-only Equals object types in descriptor form ("Lcom/x/Y;") or dotted form
     * ("com.x.Y") that are outside the broad-library set. Dynamic values resolved from another
     * delegate's .data (obfuscated/domain types) therefore qualify, while java.lang.String/int/
     * android.widget.TextView-style matchers do not.
     */
    private fun typeOnlyFieldIsNarrow(spec: FieldSpec): Boolean {
        val typeSpec = spec.type ?: return false
        if (!classSpecIsNameOnly(typeSpec)) return false
        val nameSpec = typeSpec.className ?: return false
        if (nameSpec.match != NameMatch.Equals) return false
        // Object class names only: arrays/primitives have no class metadata and must never drive a
        // class candidate (the shared helper rejects them instead of malformed L...[]; strings).
        val dotted = dottedClassNameOrNull(nameSpec.value) ?: return false
        return dotted !in BROAD_FIELD_TYPE_NAMES
    }

    private fun classDirectCandidateSources(
        spec: ClassSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        // Class-level usingStrings are intentionally NOT emitted as a class-literal SQL join here;
        // they are resolved in two canonical steps in classCandidateSources (method lookup, then
        // map the declared class), which keeps the class query a simple fast descriptor scan.
        val className = spec.className ?: return null
        val dotted = dottedClassNameOrNull(className.value) ?: return null
        val steps = mutableListOf<(SqlClassQuery) -> Unit>()
        steps += { q -> q.className(className.match.toSqlMode(), dotted) }
        if (searchPackages.isNotEmpty()) {
            val pack = searchPackages.toTypedArray()
            steps += { q -> q.searchPackages(*pack) }
        }
        return listOf(
            CandidateSource.Sql(sqlClass { steps.forEach { step -> step(this) } }.toSql()),
        )
    }

    private fun fieldCandidateSources(
        spec: FieldSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        if (spec.annotations.isNotEmpty()) {
            val sql = fieldAnnotationSql(spec.annotations)
            return listOf(CandidateSource.Descriptors(ownersWithAnnotation(sql).toList()))
        }
        // 1) readMethods/writeMethods access units (with every pushable field predicate as a
        //    conjunct) are selective. When the spec ALSO has a selective base predicate (name /
        //    declaring class / narrow type), intersect both cheap candidate sets instead of letting
        //    the broader one drive evaluation; this keeps relation evaluation to a small set.
        val accessSources = fieldAccessCandidateSources(spec, searchPackages)
        val selectiveSteps = fieldPredicateSteps(spec, searchPackages, includeBroadType = false)
        if (accessSources != null) {
            if (selectiveSteps.isEmpty()) return accessSources
            val accessDescriptors = queryDescriptors(accessSources)
            val baseDescriptors =
                queryDescriptors(
                        listOf(
                            CandidateSource.Sql(
                                sqlField { selectiveSteps.forEach { step -> step(this) } }.toSql(),
                            ),
                        ),
                    )
                    .toHashSet()
            return listOf(
                CandidateSource.Descriptors(
                    accessDescriptors.filter { it in baseDescriptors }.distinct(),
                ),
            )
        }
        // 2) Selective base predicates (name / declaring class / narrow type / searchPackages).
        if (selectiveSteps.isNotEmpty()) {
            return listOf(
                CandidateSource.Sql(
                    sqlField { selectiveSteps.forEach { step -> step(this) } }.toSql(),
                ),
            )
        }
        // 3) Broad builtin field type only as the last resort.
        val broadSteps = fieldPredicateSteps(spec, searchPackages, includeBroadType = true)
        if (broadSteps.isEmpty()) return null
        return listOf(
            CandidateSource.Sql(
                sqlField { broadSteps.forEach { step -> step(this) } }.toSql(),
            ),
        )
    }

    /**
     * Canonical pushable base predicates of a FieldSpec. Broad builtin types are included only when
     * the caller opts in (last-resort candidate, or as a necessary conjunct next to an access
     * unit).
     */
    private fun fieldPredicateSteps(
        spec: FieldSpec,
        searchPackages: List<String>,
        includeBroadType: Boolean,
    ): MutableList<(SqlFieldQuery) -> Unit> {
        val steps = mutableListOf<(SqlFieldQuery) -> Unit>()
        spec.name
            ?.takeIf { it.match == NameMatch.Equals }
            ?.let { nameSpec ->
                steps += { q -> q.name = nameSpec.value }
            }
        spec.declaredClass
            ?.takeIf(::classSpecIsNameOnly)
            ?.className
            ?.takeIf { it.match == NameMatch.Equals }
            ?.let { nameSpec ->
                dottedClassNameOrNull(nameSpec.value)?.let { dotted ->
                    steps += { q -> q.declaredClass(dotted) }
                }
            }
        spec.type
            ?.takeIf(::classSpecIsNameOnly)
            ?.className
            ?.takeIf { it.match == NameMatch.Equals }
            ?.let { nameSpec ->
                val javaName = javaTypeNameOf(nameSpec.value)
                if (
                    typeDescriptorOrNull(javaName) != null &&
                        (includeBroadType || !isBroadFieldType(javaName))
                ) {
                    steps += { q -> q.type(javaName) }
                }
            }
        val allPackages = (searchPackages + spec.searchPackages).distinct()
        if (allPackages.isNotEmpty()) {
            val pack = allPackages.toTypedArray()
            steps += { q -> q.searchPackages(*pack) }
        }
        return steps
    }

    /**
     * Field candidates driven by readMethods/writeMethods.
     *
     * IMPORTANT: the pinned engine mishandles MULTIPLE method_field_accesses units in one query
     * (each unit alone works, both ANDed returns empty / generic-plan failure). Therefore each
     * selective read/write method matcher gets its own canonical SINGLE-unit field-access query
     * (proven correct and fast-pathed), and the per-unit field descriptor sets are intersected in
     * Kotlin with deterministic order and dedupe. A single unit stays a paged SQL candidate source;
     * multiple units materialize the small intersection.
     */
    private fun fieldAccessCandidateSources(
        spec: FieldSpec,
        searchPackages: List<String>,
    ): List<CandidateSource>? {
        val unitSources = mutableListOf<CandidateSource.Sql>()
        // Adding the field's own pushable predicates (incl. a broad type as a necessary conjunct)
        // to each single-unit access query keeps the per-unit descriptor sets small.
        val baseSteps = fieldPredicateSteps(spec, searchPackages, includeBroadType = true)
        spec.readMethods.forEach { methodSpec ->
            if (!methodSpecIsSelectiveForAccessUnit(methodSpec)) return@forEach
            methodCandidateSteps(methodSpec, emptyList())?.let { methodSteps ->
                unitSources +=
                    CandidateSource.Sql(
                        sqlField {
                            baseSteps.forEach { step -> step(this) }
                            readMethod { methodSteps.forEach { step -> step(this) } }
                        }
                            .toSql(),
                    )
            }
        }
        spec.writeMethods.forEach { methodSpec ->
            if (!methodSpecIsSelectiveForAccessUnit(methodSpec)) return@forEach
            methodCandidateSteps(methodSpec, emptyList())?.let { methodSteps ->
                unitSources +=
                    CandidateSource.Sql(
                        sqlField {
                            baseSteps.forEach { step -> step(this) }
                            writeMethod { methodSteps.forEach { step -> step(this) } }
                        }
                            .toSql(),
                    )
            }
        }
        if (unitSources.isEmpty()) return null
        if (unitSources.size == 1) return unitSources
        // Intersect in Kotlin. Keep the first unit's order for deterministic candidate iteration.
        val unitFields = unitSources.map { source -> queryDescriptors(listOf(source)).toSet() }
        val ordered =
            queryDescriptors(listOf(unitSources.first()))
                .filter { descriptor -> unitFields.all { descriptor in it } }
                .distinct()
        return listOf(CandidateSource.Descriptors(ordered))
    }

    /**
     * Only selective accessor-method matchers drive a field-access unit; a modifiers-only or
     * otherwise broad matcher would scan a huge field set (same policy as broad field types).
     */
    private fun methodSpecIsSelectiveForAccessUnit(spec: MethodSpec): Boolean =
        spec.descriptor != null ||
            spec.name?.match == NameMatch.Equals ||
            spec.paramCount != null ||
            spec.paramTypes != null ||
            spec.returnType?.className != null ||
            spec.declaredClass?.className != null ||
            spec.declaredClass?.usingStrings?.any { it.value.isNotEmpty() } == true ||
            spec.usingStrings.any { it.value.isNotEmpty() } ||
            spec.usingNumbers.isNotEmpty()

    /**
     * Broad builtin field types never drive candidates when a read/write-method source is
     * available.
     */
    private fun isBroadFieldType(typeName: String): Boolean {
        val value = typeName.trim()
        if (value.isEmpty()) return true
        if (isPrimitiveOrArrayTypeName(value)) return true
        val dotted = dottedClassNameOrNull(value) ?: return true
        return BROAD_FIELD_TYPE_PREFIXES.any { prefix ->
            dotted == prefix.trimEnd('.') || dotted.startsWith(prefix)
        }
    }

    // Declared class names are derived from the member descriptor itself; no metadata document is
    // needed here (and the native method-document builder rejects array-class method refs).
    private fun declaredClassNameOfMethod(descriptor: String): String? {
        if (!isRealMethodDescriptor(descriptor)) return null
        val classDescriptor = descriptor.substring(0, descriptor.indexOf("->"))
        return dottedClassNameOrNull(classDescriptor)
    }

    private fun declaredClassNameOfField(descriptor: String): String? {
        if (!isRealFieldDescriptor(descriptor)) return null
        val classDescriptor = descriptor.substring(0, descriptor.indexOf("->"))
        return dottedClassNameOrNull(classDescriptor)
    }

    /**
     * Intersect a class candidate set with the canonical classes.field_count scan. Class specs with
     * a fieldCount constraint would otherwise load metadata for every class declaring a candidate
     * member (e.g. 9k classes for a common method signature).
     */
    private fun intersectFieldCount(
        spec: ClassSpec,
        candidates: LinkedHashSet<String>,
        scopePackages: List<String> = spec.searchPackages,
    ): LinkedHashSet<String> {
        val range = spec.fieldCount ?: return candidates
        val allowed =
            queryDescriptors(
                    listOf(CandidateSource.Sql(classFieldCountSql(range, scopePackages))),
                )
                .toHashSet()
        return candidates.filterTo(LinkedHashSet()) { it in allowed }
    }

    private fun classFieldCountSql(
        range: IntRange,
        scopePackages: List<String> = emptyList(),
    ): String {
        val pkgFilter =
            if (scopePackages.isEmpty()) {
                ""
            } else {
                val clauses = scopePackages.map { pkg ->
                    val prefix = "L" + pkg.trim('.').replace('.', '/') + "/"
                    "instr(c.descriptor, '${prefix.replace("'", "''")}') = 1"
                }
                " AND (" + clauses.joinToString(" OR ") + ")"
            }
        return "SELECT DISTINCT c.descriptor AS descriptor FROM classes c " +
            "WHERE c.field_count >= " +
            range.first +
            " AND c.field_count <= " +
            range.last +
            pkgFilter +
            " ORDER BY c.descriptor;"
    }

    /** Batch-fetch read/write access data for the direct field constraints of candidate classes. */
    private fun preloadClassFieldAccessRelations(classes: List<DexClassInfo>, spec: ClassSpec) {
        val relations = relations ?: return
        if (classes.isEmpty()) return
        if (spec.fields.none { it.readMethods.isNotEmpty() || it.writeMethods.isNotEmpty() }) return
        val fields = classes.flatMap { info -> info.fields.map { it.descriptor } }.distinct()
        if (fields.isEmpty()) return
        if (spec.fields.any { it.readMethods.isNotEmpty() }) {
            relations.fieldAccessMethods(fields, "get")
        }
        if (spec.fields.any { it.writeMethods.isNotEmpty() }) {
            relations.fieldAccessMethods(fields, "put")
        }
    }

    /** Batch-fetch read/write relation data for every candidate field once (cache-backed). */
    private fun preloadFieldAccessRelations(fieldDescriptors: List<String>, spec: FieldSpec) {
        val relations = relations ?: return
        if (fieldDescriptors.isEmpty()) return
        if (spec.readMethods.isNotEmpty()) relations.fieldAccessMethods(fieldDescriptors, "get")
        if (spec.writeMethods.isNotEmpty()) relations.fieldAccessMethods(fieldDescriptors, "put")
    }

    /**
     * Package filters are applied to the descriptor before loading the metadata document. This is
     * important for broad candidate sets (e.g. class-level string sets): classes outside the
     * requested searchPackages must never cost a native metadata read.
     */
    private fun methodDescriptorInPackages(
        descriptor: String,
        searchPackages: List<String>,
        excludePackages: List<String>,
    ): Boolean {
        if (searchPackages.isEmpty() && excludePackages.isEmpty()) return true
        val name = declaredClassNameOfMethod(descriptor) ?: return false
        return matchesPackages(name, searchPackages, excludePackages)
    }

    private fun fieldDescriptorInPackages(
        descriptor: String,
        searchPackages: List<String>,
        excludePackages: List<String>,
    ): Boolean {
        if (searchPackages.isEmpty() && excludePackages.isEmpty()) return true
        val name = declaredClassNameOfField(descriptor) ?: return false
        return matchesPackages(name, searchPackages, excludePackages)
    }

    private fun classDescriptorInPackages(
        descriptor: String,
        searchPackages: List<String>,
        excludePackages: List<String>,
    ): Boolean {
        if (searchPackages.isEmpty() && excludePackages.isEmpty()) return true
        if (descriptor.startsWith("[")) return false
        val name = dottedClassNameOrNull(descriptor) ?: return false
        return matchesPackages(name, searchPackages, excludePackages)
    }

    private fun unsupportedCandidate(kind: String): Nothing =
        throw UnsupportedOperationException(
            "Query matcher " +
                kind +
                " candidate shape is unsupported: the spec has no fast-path " +
                "predicate (method: name/modifiers/declaredClass className|usingStrings|" +
                "usingNumbers|searchPackages/returnType className/paramCount/paramTypes/usingStrings/" +
                "usingNumbers/searchPackages; class: className/searchPackages/class usingStrings|usingNumbers/" +
                "cheap nested members/superClass; field: name/declaredClass/type/searchPackages). Add one, " +
                "or extend the matcher helper with a canonical fast-path shape.",
        )
}

// ---------------------------------------------------------------------------
// Canonical SQL predicate helpers (delegating to the typed SQL DSL)
// ---------------------------------------------------------------------------

private fun NameMatch.toSqlMode(): SqlStringMatchMode =
    when (this) {
        NameMatch.Equals -> SqlStringMatchMode.Equals
        NameMatch.StartsWith -> SqlStringMatchMode.StartsWith
        NameMatch.Contains -> SqlStringMatchMode.Contains
        NameMatch.EndsWith -> SqlStringMatchMode.EndsWith
    }

private fun addMethodStringPredicate(query: SqlMethodQuery, spec: StringSpec) {
    when (spec.match) {
        NameMatch.Equals -> query.usingEqStrings(spec.value)
        NameMatch.StartsWith -> query.usingPrefixStrings(spec.value)
        NameMatch.Contains -> query.usingStrings(spec.value)
        NameMatch.EndsWith -> query.usingSuffixStrings(spec.value)
    }
}

private fun SqlClassLiteralConstraint.addClassLiteralStrings(strings: List<StringSpec>) {
    strings.forEach { spec ->
        when (spec.match) {
            NameMatch.Equals -> usingEqStrings(spec.value)
            NameMatch.StartsWith -> usingPrefixStrings(spec.value)
            NameMatch.Contains -> usingStrings(spec.value)
            NameMatch.EndsWith -> usingSuffixStrings(spec.value)
        }
    }
}

private fun classSpecIsNameOnly(spec: ClassSpec): Boolean =
    spec.className != null &&
        spec.noneOf.isEmpty() &&
        spec.annotations.isEmpty() &&
        spec.annotationCount == null &&
        spec.superClass == null &&
        spec.interfaces.isEmpty() &&
        spec.fields.isEmpty() &&
        spec.methods.isEmpty() &&
        spec.fieldCount == null &&
        spec.methodCount == null &&
        spec.interfaceCount == null &&
        spec.modifiers == null &&
        spec.usingStrings.isEmpty() &&
        spec.usingNumbers.isEmpty() &&
        spec.searchPackages.isEmpty() &&
        spec.excludePackages.isEmpty()

private fun matchesPackages(
    javaName: String,
    searchPackages: List<String>,
    excludePackages: List<String> = emptyList(),
): Boolean =
    (searchPackages.isEmpty() ||
        searchPackages.any { javaName == it || javaName.startsWith("$it.") }) &&
        (excludePackages.isEmpty() ||
            excludePackages.none { javaName == it || javaName.startsWith("$it.") })

// ---------------------------------------------------------------------------
// Paging and cheap raw-document prefiltering
// ---------------------------------------------------------------------------

private fun pagedSql(sql: String, pageSize: Int, offset: Int): String {
    val base = sql.trim().removeSuffix(";")
    return "$base LIMIT $pageSize OFFSET $offset;"
}

private fun JsonObject.stringValue(key: String): String? =
    (this[key] as? JsonPrimitive)?.contentOrNull

private fun JsonObject.intValue(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

private fun JsonObject.stringList(key: String): List<String> =
    (this[key] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } ?: emptyList()

private fun JsonObject.objectValue(key: String): JsonObject? = this[key] as? JsonObject

/** searchPackages/excludePackages semantics on one raw document name field (dotted Java names). */
private fun JsonObject.nameMatchesPackages(
    key: String,
    searchPackages: List<String>,
    excludePackages: List<String>,
): Boolean {
    if (searchPackages.isEmpty() && excludePackages.isEmpty()) return true
    val name = stringValue(key) ?: return false
    return matchesPackages(name, searchPackages, excludePackages)
}

/** Cheap necessary-condition prefilter on the raw method document (no model construction). */
private fun methodPrefilter(json: JsonObject, spec: MethodSpec): Boolean {
    if (
        !json.nameMatchesPackages("declared_class_name", spec.searchPackages, spec.excludePackages)
    ) {
        return false
    }
    spec.descriptor?.let { if (json.stringValue("descriptor") != it) return false }
    spec.name
        ?.takeIf { it.match == NameMatch.Equals }
        ?.let {
            if (json.stringValue("name") != it.value) return false
        }
    spec.modifiers?.let { mask ->
        val modifiers = json.intValue("modifiers") ?: return@let
        if (modifiers and mask != mask) return false
    }
    spec.paramCount?.let { range ->
        val count = json.intValue("param_count") ?: return@let
        if (count !in range) return false
    }
    spec.paramTypes
        ?.takeIf { types -> types.all { it == null || it.match == NameMatch.Equals } }
        ?.let { types ->
            val names = json.stringList("param_type_names")
            if (names.size != types.size) return false
            types.forEachIndexed { index, type ->
                if (type != null && !typeSpecMatchesJavaName(type, names[index])) return false
            }
        }
    spec.declaredClass?.takeIf(::classSpecIsNameOnly)?.className?.let {
        val name = json.stringValue("declared_class_name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    spec.returnType?.takeIf(::classSpecIsNameOnly)?.className?.let {
        val name = json.stringValue("return_type_name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    if (spec.usingStrings.isNotEmpty()) {
        val strings = json.stringList("using_strings")
        for (stringSpec in spec.usingStrings) {
            if (strings.none { stringSpec.matches(it) }) return false
        }
    }
    // Opcode/annotation keys are additive metadata; missing/null data cannot satisfy a constraint.
    spec.opcodes?.let { opcodeSpec ->
        val count = json.intValue("opcode_count") ?: return false
        opcodeSpec.count?.let { if (count !in it) return false }
    }
    if (spec.annotations.isNotEmpty()) {
        val annotations = json["annotations"] as? JsonArray ?: return false
        if (annotations.isEmpty()) return false
    }
    return true
}

/** Cheap necessary-condition prefilter on the raw class document. */
private fun classPrefilter(json: JsonObject, spec: ClassSpec): Boolean {
    if (!json.nameMatchesPackages("name", spec.searchPackages, spec.excludePackages)) return false
    spec.className?.let {
        val name = json.stringValue("name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    spec.modifiers?.let { mask ->
        val modifiers = json.intValue("modifiers") ?: return@let
        if (modifiers and mask != mask) return false
    }
    spec.methodCount?.let { range ->
        val size = (json["methods"] as? JsonArray)?.size ?: return@let
        if (size !in range) return false
    }
    spec.fieldCount?.let { range ->
        val size = (json["fields"] as? JsonArray)?.size ?: return@let
        if (size !in range) return false
    }
    spec.interfaceCount?.let { range ->
        val size = (json["interfaces"] as? JsonArray)?.size ?: return@let
        if (size !in range) return false
    }
    spec.superClass?.takeIf(::classSpecIsNameOnly)?.className?.let {
        val name = json.objectValue("super_class")?.stringValue("name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    if (spec.interfaces.isNotEmpty()) {
        val interfaceArray = json["interfaces"] as? JsonArray ?: return true
        val interfaceNames = interfaceArray.mapNotNull { (it as? JsonObject)?.stringValue("name") }
        for (interfaceSpec in spec.interfaces) {
            val interfaceName = interfaceSpec.className ?: continue
            if (!classSpecIsNameOnly(interfaceSpec)) continue
            if (interfaceNames.none { nameSpecMatchesJavaName(interfaceName, it) }) return false
        }
    }
    if (spec.annotations.isNotEmpty()) {
        val annotations = json["annotations"] as? JsonArray ?: return false
        if (annotations.isEmpty()) return false
    }
    return true
}

/** Cheap necessary-condition prefilter on the raw field document. */
private fun fieldPrefilter(json: JsonObject, spec: FieldSpec): Boolean {
    if (
        !json.nameMatchesPackages("declared_class_name", spec.searchPackages, spec.excludePackages)
    ) {
        return false
    }
    spec.name
        ?.takeIf { it.match == NameMatch.Equals }
        ?.let {
            if (json.stringValue("name") != it.value) return false
        }
    spec.modifiers?.let { mask ->
        val modifiers = json.intValue("modifiers") ?: return@let
        if (modifiers and mask != mask) return false
    }
    spec.type?.takeIf(::classSpecIsNameOnly)?.className?.let {
        val name = json.stringValue("type_name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    spec.declaredClass?.takeIf(::classSpecIsNameOnly)?.className?.let {
        val name = json.stringValue("declared_class_name") ?: return@let
        if (!nameSpecMatchesJavaName(it, name)) return false
    }
    return true
}
