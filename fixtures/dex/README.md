# DEX fixtures

Small DEX files used by the JNI integration tests. They are copied from
dexsql-rs (`fixtures/dex`), where they back the engine's metadata API tests.

* `alpha.dex` defines `fixtures.Alpha` (fields, constructors, a static
  initializer, synchronized methods, string/number/field uses, duplicate
  invokes) and the `fixtures.Gamma` interface.
* `beta.dex` defines `fixtures.Beta extends fixtures.Alpha`. It only contains
  references to `Alpha`, so it exercises cross-DEX method/field resolution and
  the DexKit-style caller import order.
* `annotated.dex` defines `fixtures.Annotated` and the runtime annotation
  interface `fixtures.Meta`. `Annotated` has array `clone()` invokes
  (`[I` and `[Lfixtures/Meta;` declaring classes), a generic class signature,
  runtime class/method annotations with string-array elements, and methods with
  known instruction streams for the opcode metadata tests.

Regenerate from `src/` with a JDK and Android build-tools `d8` (this is what
produced the committed files; d8 desugars string concatenation, so regenerating
with a different d8 version can change instruction-level relations):

```sh
cd fixtures/dex
rm -rf build && mkdir -p build/classes build/alpha build/beta build/annotated
javac -source 8 -target 8 -d build/classes src/fixtures/*.java
D8="${ANDROID_HOME:-$HOME/android-sdk}/build-tools/35.0.0/d8"
"$D8" --min-api 28 --output build/alpha build/classes/fixtures/Alpha.class build/classes/fixtures/Gamma.class
"$D8" --min-api 28 --output build/beta build/classes/fixtures/Beta.class
"$D8" --min-api 28 --output build/annotated build/classes/fixtures/Annotated.class build/classes/fixtures/Meta.class
cp build/alpha/classes.dex alpha.dex
cp build/beta/classes.dex beta.dex
cp build/annotated/classes.dex annotated.dex
```
