<div align="center">

# apk-self-reinforce-plugin

**纯 JVM 实现的 Android APK 自研加固 Gradle 插件 · 不依赖任何第三方加固二进制**

DEX 整体加密 · 壳 Application 入口替换 · 防重打包 · 反调试/反动态注入 · assets 资源加密 · 重签名

</div>

---

## 特性

| 能力 | 说明 |
|---|---|
| 🔒 **DEX 整体加密** | 原始 `classes*.dex` → AES/CBC 加密为 `assets/selfprotect/payload.dat`，运行时解密加载（多 dex 数字序） |
| 🛡 **防重打包** | 打包时提取签名证书 SHA-256（XOR 掩码存储），壳启动比对 `PackageManager` 实际签名，不一致立即杀进程 |
| 🚫 **基础反调试** | `debuggable` 标志 / `Debug.isDebuggerConnected` / `TracerPid` 检测，命中即杀 |
| 🚫 **反动态注入** | 扫描 `/proc/self/maps` 的 frida / xposed / substrate / zygisk 特征库 + hook 框架类探测 |
| 🔐 **载荷完整性** | payload 密文 SHA-256（掩码存储）预置，壳解密前校验，防 APK 内载荷被整体替换 |
| 📦 **assets 资源加密** | 白名单内 assets 加密为 `assets/enc/*`，`SecureAssets.open()` 透明解密，可增量接入 |
| ✏️ **Manifest 入口替换** | 自写二进制 AXML 解析器：application name → 壳 `StubApplication`，`appComponentFactory` → 框架默认 |
| 📝 **重签名** | zipalign（`-P 16 4` 页对齐）+ apksigner（v1/v2） |

## 原理

```
打包侧（Gradle Task / CLI，纯 JVM）
 1. 壳源码 --javac(android.jar)--> class --d8--> 壳 classes.dex
 2. 原始 classes*.dex --zip--> AES 加密 --> assets/selfprotect/payload.dat
    AxmlEditor 二进制改写 Manifest：application name → 壳 StubApplication
    原 Application 全限定名 --> assets/selfprotect/config.txt
    签名指纹(SHA-256, XOR 掩码) --> assets/selfprotect/expected_sig.txt
    payload 密文哈希(XOR 掩码)  --> assets/selfprotect/payload_hash.txt
    白名单 assets --> AES 加密 --> assets/enc/* + assets_map.txt
 3. zipalign + apksigner 重签

运行侧（壳，随 APK 打包）
 StubApplication.attachBaseContext()
   ├─ 安全校验：反调试 → 反动态注入 → 签名指纹 → payload 哈希，任一命中 killProcess
   ├─ 解密 payload.dat → payload.zip（原 dex）
   ├─ DexClassLoader(parent=原 loader) + 替换 LoadedApk.mClassLoader
   └─ 反射实例化原 Application 并 attach
 StubApplication.onCreate()
   └─ 修正 framework 引用（mInitialApplication/mAllApplications/mOuterContext）→ 原 Application.onCreate()
```

## 快速开始

### 环境要求

- JDK 17+
- Android SDK（含 `platforms/android-XX/android.jar` 与 `build-tools`，自动探测或手动指定 `sdkDir`）
- 可选：用于重签名的 keystore

### 方式一：命令行（不接入工程，直接加固）

```bash
git clone https://github.com/funfunfunnylsh/apk-self-reinforce-plugin.git
cd apk-self-reinforce-plugin

sh gradlew :selfReinforceCli \
  -PinputApk=/path/app-release.apk \
  -PoutputApk=/path/app-selfprotect.apk \
  -Pks=/path/keystore -PksPass=xxx -Palias=xxx -PkeyPass=xxx \
  -PencryptedAssets=maps/,config.json
```

参数说明：

| 参数 | 必填 | 说明 |
|---|---|---|
| `inputApk` | ✅ | 待加固的 release APK（需已签名，用于提取指纹） |
| `outputApk` | ✅ | 输出路径 |
| `ks/ksPass/alias/keyPass` | 可选 | keystore 重签名；不传则输出对齐后的未签名包（不预置防重打包指纹） |
| `encryptedAssets` | 可选 | 需要加密的 assets 路径（前缀/精确匹配，逗号分隔） |
| `sdkDir` | 可选 | Android SDK 路径，默认自动探测 |

### 方式二：接入业务 app 模块

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}

// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("com.cdtec.plugin.apk-self-reinforce")
}

selfReinforce {
    inputApk.set(layout.buildDirectory.file("outputs/apk/release/app-release.apk"))
    outputApk.set(layout.buildDirectory.file("outputs/apk/release/app-selfprotect.apk"))
    storeFile.set(file("xxx.keystore"))
    storePassword.set("...")
    keyAlias.set("...")
    keyPassword.set("...")
    encryptedAssets.addAll(listOf("maps/", "config.json")) // 可选
}
```

执行 `./gradlew selfReinforceApk`。

### 方式三：远程直接引用（JitPack，无需 clone 仓库）

插件已发布到 [JitPack](https://jitpack.io/#funfunfunnylsh/apk-self-reinforce-plugin)，可直接从远程拉取：

```kotlin
// settings.gradle.kts（或根 build.gradle.kts 顶部）
buildscript {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
    dependencies {
        classpath("com.github.funfunfunnylsh:apk-self-reinforce-plugin:v1.0.0")
    }
}

// app/build.gradle.kts
apply(plugin = "com.cdtec.plugin.apk-self-reinforce")
```

Groovy 写法：

```groovy
// 根 build.gradle
buildscript {
    repositories { maven { url 'https://jitpack.io' } }
    dependencies { classpath 'com.github.funfunfunnylsh:apk-self-reinforce-plugin:v1.0.0' }
}
apply plugin: 'com.cdtec.plugin.apk-self-reinforce'
```

然后同样配置 `selfReinforce { ... }` 扩展即可。版本号对应 GitHub tag（当前 `v1.0.0`）。

### assets 资源加密的业务接入

```java
// 原：context.getAssets().open("maps/city.dat")
// 加密后必须走壳提供的透明解密 API：
InputStream in = com.selfprotect.SecureAssets.open(context, "maps/city.dat");
```

> 注意：白名单外的 assets 不受影响（原样直读）；白名单内的路径必须走 `SecureAssets.open()`，否则 `AssetManager` 直开会 `FileNotFoundException`。

## 安全密钥配置

AES 密钥由 `KEY_PART xor KEY_MASK` 派生（两端各一份，必须同步修改）：

| 常量 | 打包侧 | 壳侧 |
|---|---|---|
| AES 密钥 | `core/PayloadCrypto.kt` | `ShellCrypto.java` |
| 指纹掩码 | `core/ApkReinforcer.kt` → `SIG_MASK` | `StubApplication.java` → `SIG_MASK` |
| 哈希掩码 | `core/ApkReinforcer.kt` → `PAYLOAD_MASK` | `StubApplication.java` → `PAYLOAD_MASK` |

**正式使用前务必更换默认密钥**，且两侧保持一致。

## 目录结构

```
apk-self-reinforce-plugin/
├── build.gradle.kts                  # Gradle 插件定义 + CLI 任务
├── src/main/kotlin/com/cdtec/selfreinforce/
│   ├── SelfReinforcePlugin.kt        # 插件入口（selfReinforce 扩展）
│   ├── SelfReinforceTask.kt          # Gradle Task
│   ├── ReinforceCli.kt               # 命令行入口
│   └── core/
│       ├── ReinforcePipeline.kt      # 流水线编排（壳编译→加固→对齐→重签）
│       ├── ApkReinforcer.kt          # APK 重建：dex 抽取加密/指纹/哈希/assets 加密
│       ├── AxmlEditor.kt             # 二进制 AXML 解析与字符串池重建
│       ├── PayloadCrypto.kt          # AES 加解密（打包侧）
│       ├── ShellDexBuilder.kt        # javac + d8 编译壳 dex
│       └── Signer.kt                 # zipalign + apksigner
└── src/main/resources/shell/com/selfprotect/
    ├── StubApplication.java          # 壳 Application（安全校验 + 加载 + 接力）
    ├── ShellCrypto.java              # AES 解密（壳侧）
    └── SecureAssets.java             # assets 透明解密 API
```

## 已知限制

- 一代壳：DEX 整体加密，未做方法级 VMP / 抽取；对抗内存 dump 需 native 层。
- 载荷解密后落盘 `files/selfprotect/payload.zip`；可升级 API≥26 走 `InMemoryDexClassLoader` 不落盘。
- 反调试/反动态注入为 Java 层基础检测，对抗 Xposed/Frida 的主动分析需 native 化（Roadmap 见下）。

## Roadmap

- [ ] 壳核心逻辑 native 化（解密/校验/loader 安装下沉 .so，JNI 完成）
- [ ] API≥26 内存加载 dex（InMemoryDexClassLoader 不落盘）
- [ ] 敏感方法抽取到 native 执行
- [ ] 模拟器/root 检测、运行环境安全

## License

[MIT](LICENSE)
