# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Full build + tests (CI runs this)
./gradlew build

# Run all tests
./gradlew test

# Run a single test class / single test method
./gradlew test --tests "com.cdtec.selfreinforce.core.AxmlEditorTest"
./gradlew test --tests "com.cdtec.selfreinforce.core.AxmlEditorTest.替换application入口并返回原值"

# CLI reinforce (no host project needed; needs Android SDK + optionally a keystore)
./gradlew :selfReinforceCli \
  -PinputApk=/path/app-release.apk \
  -PoutputApk=/path/out.apk \
  -Pks=/path/ks -PksPass=xxx -Palias=xxx -PkeyPass=xxx \
  -PencryptedAssets=maps/,config.json \
  -Pchannels=oppo,xiaomi

# When applied to a host app project
./gradlew selfReinforceApk
```

Toolchain: JDK 17, Kotlin DSL, plugin targets Java 8 sourceCompatibility. AGP is `compileOnly` (`com.android.tools.build:gradle:8.7.3`) — provided by the host project at runtime, never bundled.

Android SDK discovery order: `ANDROID_HOME` → `ANDROID_SDK_ROOT` → `local.properties` `sdk.dir` → `~/Library/Android/sdk`. Shell DEX build needs `platforms/android-XX/android.jar` (highest version auto-selected) and `build-tools/XX/{d8,zipalign,lib/apksigner.jar}`.

## Architecture

This is a **two-side** APK reinforcement system. The pack side is Kotlin/JVM (this plugin, runs at build time); the shell side is Java/Android (compiled to DEX and embedded in the produced APK as the new entry point). Both sides must stay in sync on crypto material and masking constants.

### Pack-time pipeline (`core/ReinforcePipeline.kt`)

Single entry point shared by both `SelfReinforceTask` (Gradle plugin) and `ReinforceCli` (CLI `main`). Four phases:

1. **Shell DEX build** (`ShellDexBuilder`): `javac` (classpath = `android.jar`) → `d8` (`--min-api 21`). Sources are released from `src/main/resources/shell/com/selfprotect/*.java` to a work dir.
2. **APK reinforce** (`ApkReinforcer`): open input APK with `ZipFile`, then:
   - Extract all `classes*.dex` in **numeric order** (`classes.dex, classes2.dex, ..., classes10.dex`) — lexicographic sort would put `classes10.dex` before `classes2.dex` and break the runtime dex load order.
   - Zip them, AES-encrypt to `assets/selfprotect/payload.dat`.
   - `AxmlEditor` rewrites binary `AndroidManifest.xml`: `application android:name` → `com.selfprotect.StubApplication`; original name → `assets/selfprotect/config.txt`. If `<application>` has no `android:name`, a new attribute is inserted into the start-tag chunk. `appComponentFactory` is forced to `android.app.AppComponentFactory` because the original (e.g. androidx `CoreComponentFactory`) was extracted with the original DEX and would crash the framework's early ClassLoader setup.
   - Strip old v1 signature entries (`META-INF/*.SF|*.RSA|*.DSA`, `MANIFEST.MF`). Copy all other entries preserving STORED/DEFLATED method and timestamps.
   - Encrypt whitelisted assets to `assets/enc/*`, write `assets/selfprotect/assets_map.txt`.
   - Write XOR-masked signature fingerprint and payload SHA-256.
3. **zipalign** (`-P 16 4` for 16KB page .so alignment) + **apksigner** (v1+v2, v3 disabled).
4. **Multi-channel** (`ChannelWriter`, optional): walle-style APK Signing Block pair (ID `0x71777777`), no re-signing. EOCD `cdOffset` is patched; works on v2-signed, v1-only, and unsigned APKs.

Signing resolution (`SelfReinforceTask.resolveSigning`): explicit `storeFile` etc. → AGP `signingConfigs.release` → `~/.android/debug.keystore` → none (output is aligned-only, no anti-repackage fingerprint embedded).

### Run-time shell (`src/main/resources/shell/com/selfprotect/`)

`StubApplication` does a two-phase handoff (this is the trickiest part of the whole system):

- **`attachBaseContext`**: run security checks (`detectDebugging` / `detectDynamicHooks` / `verifySignature` / `verifyPayloadHash`; any hit → `Process.killProcess`), `SecureAssets.init`, `bypassHiddenApi`, decrypt `payload.dat` → `files/selfprotect/payload.zip`, create `DexClassLoader(parent = oldLoader)` and replace `LoadedApk.mClassLoader` via reflection, then instantiate the original Application and call `attach(base)`.
- **`onCreate`**: framework's `makeApplication` has by now overwritten `mInitialApplication`/`mAllApplications`/`mOuterContext` with the shell instance — `fixApplicationReferences` repairs them to point at the real Application, then calls its `onCreate()`. Skipping this step causes `ClassCastException` when SDKs cast `ActivityThread.currentApplication()` to the user's Application class.

`SecureAssets` provides transparent asset decryption: business code calls `SecureAssets.open(ctx, "maps/city.dat")` instead of `AssetManager.open`. Whitelisted paths bypass this and crash on direct open — the encrypted file at `assets/enc/...` is not visible to `AssetManager`.

### Constants that must stay in sync across the two sides

Changing any of these in one place and not the other silently breaks runtime:

| Constant | Pack side | Shell side |
|---|---|---|
| AES key (`KEY_PART xor KEY_MASK`, 16B) | `core/PayloadCrypto.kt` | `ShellCrypto.java` |
| `SIG_MASK` (32B, applied to SHA-256 of signing cert) | `core/ApkReinforcer.kt` | `StubApplication.java` |
| `PAYLOAD_MASK` (32B, applied to SHA-256 of payload ciphertext) | `core/ApkReinforcer.kt` | `StubApplication.java` |
| Asset paths (`payload.dat`, `config.txt`, `expected_sig.txt`, `payload_hash.txt`, `assets_map.txt`, `assets/enc/`) | `ApkReinforcer` constants | `StubApplication` / `SecureAssets` string literals |

The default key/mask values in the repo are public — production deployments must replace all of them.

### Binary AXML editing (`core/AxmlEditor.kt`)

Hand-written binary AXML parser/editor. Only the string pool is rebuilt — the XML body bytes are untouched (attribute values are string-pool indices). Handles UTF-8 and UTF-16LE string pools (selected by `UTF8_FLAG`). When inserting a new `android:name` attribute (default-Application case), it appends `name`/`ANDROID_NS`/shell-class strings to the pool, then writes a 20-byte `ResXMLTree_attribute` at the end of the `<application>` start-tag chunk and patches `attributeCount` and chunk `size` in place.

### Multi-channel (`core/ChannelWriter.kt`)

Replicates walle's APK Signing Block scheme with a custom pair ID (`0x71777777`) and a UTF-8 value (not protobuf — not interoperable with walle readers). Locates EOCD by scanning backwards for the signature, validates the `APK Sig Block 42` magic, replaces or inserts the pair, and rewrites the EOCD `cdOffset`. The block sits between the zip contents and the Central Directory, which v2/v3 signatures do not cover — so existing signatures stay valid without re-signing.

## Testing

JUnit 4. Tests rely on real binary `AndroidManifest.xml` samples in `src/test/resources/` (one with a custom Application, one without `android:name`). The AXML test asserts idempotency (running the editor on its own output must produce identical bytes and round-trip the original name). `ChannelWriterTest` builds a fake in-memory zip and verifies EOCD/CD integrity via `ZipFile`.

## Notes

- The shell is a "first-generation" shell: whole-DEX encryption, no method-level VMP. Payload decrypts to `files/selfprotect/payload.zip` on disk — `InMemoryDexClassLoader` (API ≥26) is on the roadmap.
- Anti-debug/anti-hook checks are Java-layer and baseline-only; determined analysis with Frida/Xposed still requires native hardening (roadmap).
- Published to JitPack as `com.github.funfunfunnylsh:apk-self-reinforce-plugin:v1.0.0`. The `publication.artifactId` is intentionally aligned with the repo name for JitPack rewriting.
