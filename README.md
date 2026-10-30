# dexsql

Kotlin/JVM and Android bindings for [dexsql-rs](https://github.com/Ujhhgtg/dexsql-rs), a DEX/APK
SQL engine, plus a DexKit-style query matcher and a SQL DSL built on top of it.

The Rust engine only executes read-only SQL. This library adds:

- `DexSqlBridge`: owns one native dataset; runs SQL and reads class/method/field metadata.
- `dev.ujhhgtg.dexsql.meta`: typed metadata (`DexClassInfo`, `DexMethodInfo`, `DexFieldInfo`).
- `dev.ujhhgtg.dexsql.matcher`: `ClassMatcher`/`MethodMatcher`/`FieldMatcher` builders and
  `DexMatcherSession` for `findClasses`/`findMethods`/`findFields`.
- `dev.ujhhgtg.dexsql.sql`: `sqlMethod { }`/`sqlClass { }`/`sqlField { }`/`sqlConstructor { }`,
  which emit canonical DexSQL text.

## Artifacts

| Coordinates                                | Contents                                        |
| ------------------------------------------ | ----------------------------------------------- |
| `dev.ujhhgtg:dexsql`                       | JVM library (no native code)                    |
| `dev.ujhhgtg:dexsql-android`               | AAR with `libdexsql_jni.so` for arm64-v8a, x86_64 |
| `dev.ujhhgtg:dexsql-natives-linux-x86_64`  | Host JNI library for desktop JVMs               |

```kotlin
dependencies {
    // Android
    implementation("dev.ujhhgtg:dexsql-android:<version>")
    // Desktop JVM (Linux x86_64)
    implementation("dev.ujhhgtg:dexsql:<version>")
    runtimeOnly("dev.ujhhgtg:dexsql-natives-linux-x86_64:<version>")
}
```

The native library is loaded on first use, in this order: `DexSqlLibrary.load(file)`, the
`dexsql.library.path` system property, a bundled natives jar on the classpath, then
`System.loadLibrary("dexsql_jni")`.

## Usage

```kotlin
DexSqlBridge.open("app.apk").use { bridge ->
    val rows = bridge.query(sqlMethod { declaredClass = "com.example.Foo"; usingEqStrings("tag") }.toSql())

    DexMatcherSession(bridge).use { session ->
        val methods = session.findMethods {
            declaredClass("com.example.Foo")
            usingStrings("tag")
        }
        methods.forEach { println(it.descriptor) }
    }
}
```

On Android, `DexSqlBridge.open(applicationInfo)` (from `dexsql-android`) opens the base and split APKs.

## Building

Requires JDK 21, a Rust toolchain (`rustup`; `native/rust-toolchain.toml` pins the channel and
targets) and, for the AAR, the Android SDK with the NDK version in `gradle/libs.versions.toml`.

```sh
./gradlew build                # JVM library, host natives, AAR, tests
./gradlew publishToMavenLocal
```

Gradle builds `native/` with Cargo. The Android linker, `CC`, `CXX` and `AR` are passed to Cargo as
`CARGO_TARGET_<TRIPLE>_LINKER`/`CC_<triple>`/... environment variables derived from the NDK; no
`.cargo/config.toml` is used. Variables you already export take precedence. Override the Cargo
executable with `-Pdexsql.cargo=...` and the toolchain with `-Pdexsql.rustToolchain=...`.

## Releasing

Push a `vX.Y.Z` tag. The `Release` workflow tests, signs and publishes every module to Maven
Central, then creates a GitHub release.

## License

Apache-2.0
