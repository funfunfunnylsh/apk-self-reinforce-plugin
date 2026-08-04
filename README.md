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
| 🧬 **native 壳层** | 解密/完整性/安全检测在 `libselfprotect.so`（NDK 编译，双 ABI），密钥编译进 so（混淆存储），Frida hook Java 层拿不到密钥与明文 |
| 💾 **载荷不落盘** | API 26+ `InMemoryDexClassLoader(ByteBuffer[])` 内存加载；API<26 native `memfd_create` + `/proc/self/fd/N`，全程无明文文件落盘 |
| 🚫 **native 反调试** | `ptrace(TRACEME)` 自附加 + 后台线程轮询 `TracerPid` + frida/gadget maps 特征 + 27042 端口探测，命中即杀 |
| 🧭 **反模拟器/反 root** | `ro.kernel.qemu`/`goldfish`/`ranchu` 等模拟器特征；`su` 路径/Magisk/mounts 检测 |
| 🛡 **防重打包** | 打包时提取签名证书 SHA-256（XOR 掩码存储），壳启动比对 `PackageManager` 实际签名，不一致立即杀进程 |
| 🔐 **载荷完整性** | payload 密文 SHA-256（native 计算，掩码存储）预置，壳解密前校验，防 APK 内载荷被整体替换 |
| 📦 **assets 资源加密** | 白名单内 assets 加密为 `assets/enc/*`，`SecureAssets.open()` 透明解密，可增量接入 |
| 📦 **多渠道打包** | 复刻 walle：直接写 APK Signing Block（ID 0x71777777），无需重签名；支持配置列表 + txt 文件 |
| 🧭 **运行时读渠道** | 插件自动注入 `ChannelReader`，App 内 `ChannelReader.getChannel(this)` 直接读取（walle 兼容） |
| 📤 **蒲公英上传** | 可选：直连 apiv2 API 上传 + 轮询发布状态，输出下载短链/二维码 |
| 🔔 **钉钉通知** | 可选：构建完成发 markdown 到群机器人，支持「加签」安全设置 |
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
  -PencryptedAssets=private/,config.bin \
  -Pchannels=oppo,xiaomi -PchannelsFile=/path/channels.txt \
  -PpgyerApiKey=xxx -PdingTalkWebhook='https://oapi.dingtalk.com/robot/send?access_token=xxx'
```

参数说明：

| 参数 | 必填 | 说明 |
|---|---|---|
| `inputApk` | ✅ | 待加固的 release APK（需已签名，用于提取指纹） |
| `outputApk` | ✅ | 输出路径 |
| `ks/ksPass/alias/keyPass` | 可选 | keystore 重签名；不传则输出对齐后的未签名包（不预置防重打包指纹） |
| `encryptedAssets` | 可选 | 需要加密的 assets 路径（前缀/精确匹配，逗号分隔） |
| `channels` | 可选 | 多渠道列表（逗号分隔），产渠道包（写入 Signing Block，无需重签名） |
| `channelsFile` | 可选 | 多渠道 txt 文件（每行一个渠道，支持 `#` 注释），与 channels 合并去重 |
| `channelOutputDir` | 可选 | 渠道包输出目录，默认 outputApk 同目录 `channels/` |
| `pgyerApiKey` | 可选 | 蒲公英 API Key，配置后上传主包到蒲公英并轮询出下载链接 |
| `pgyerInstallType` | 可选 | 蒲公英安装类型：1公开 2密码 3邀请（默认 2） |
| `pgyerInstallPassword` | 可选 | 蒲公英密码安装时的密码 |
| `pgyerUpdateDescription` | 可选 | 蒲公英更新说明 |
| `pgyerUploadAllChannels` | 可选 | true 时所有渠道包也上传蒲公英（默认只传主包） |
| `dingTalkWebhook` | 可选 | 钉钉群机器人 webhook（含 access_token），配置后发送 markdown 通知 |
| `dingTalkSecret` | 可选 | 钉钉机器人「加签」密钥，配置后自动附加 timestamp/sign |
| `dingTalkKeyword` | 可选 | 通知标题关键字（默认 Android） |
| `sdkDir` | 可选 | Android SDK 路径，默认自动探测 |

### 运行时读取渠道（App 内直接调用）

插件会在打包阶段自动生成 `ChannelReader` 源码（`build/generated/selfprotect/java`）并加入
app 的 main sourceSets，**无需任何额外依赖**，业务代码直接调用：

```kotlin
// Kotlin
val channel = com.selfprotect.reinforce.ChannelReader.getChannel(this)
```

```java
// Java
String channel = com.selfprotect.reinforce.ChannelReader.getChannel(this); // Context
String channel = com.selfprotect.reinforce.ChannelReader.getChannel(apkPath); // 纯 Java
```

- 渠道来源于 APK v2 Signing Block 的 `0x71777777` 条目（walle 兼容），读取自身 APK 文件，无网络、无反射、无额外权限
- 未写入渠道（未配置多渠道）时返回 `null`，业务侧判空即可
- 与 [walle](https://github.com/Meituan-Dianping/walle) 的 `WalleChannelReader` 读取同一数据格式，互操作

### 方式二：接入业务 app 模块

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}

// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("com.selfprotect.reinforce")
}

selfReinforce {
    // 全部可选，均有默认值：
    // - inputApk  默认取 build/outputs/apk/release 最新 APK
    // - outputApk 默认 inputApk 同目录 app-selfprotect.apk
    // - 签名优先级：显式配置 > android signingConfigs(release) > ~/.android/debug.keystore
    // - autoBuildRelease 默认 true：selfReinforceApk 自动先跑 assembleRelease
    inputApk.set(layout.buildDirectory.file("outputs/apk/release/app-release.apk"))
    outputApk.set(layout.buildDirectory.file("outputs/apk/release/app-selfprotect.apk"))
    encryptedAssets.addAll(listOf("private/", "config.bin")) // 可选

    // 打包阶段集成（可选）
    // autoBuildRelease.set(false)          // 关闭自动依赖 assembleRelease
    // hookToAssembleRelease.set(true)      // 开启后跑 assembleRelease 末尾自动加固

    // 多渠道（可选）：配置 + txt 文件
    channels.addAll(listOf("oppo", "xiaomi"))
    channelFile.set(layout.projectDirectory.file("channels.txt"))

    // 蒲公英上传（可选，配置 apiKey 即启用）
    pgyerApiKey.set("你的蒲公英APIKey")
    pgyerInstallPassword.set("123456")
    pgyerUpdateDescription.set("自研加固 v1.0")

    // 钉钉通知（可选，配置 webhook 即启用）
    dingTalkWebhook.set("https://oapi.dingtalk.com/robot/send?access_token=xxx")
    dingTalkSecret.set("SECxxx")   // 可选加签
    dingTalkKeyword.set("DemoApp")
}
```

**一条命令全链路**（自动完成 打包 → 加固 → 重签名 → 多渠道 → 可选发布/通知）：

```bash
./gradlew :app:selfReinforceApk
```

也可在 `selfReinforce` 中开启 `hookToAssembleRelease.set(true)`，之后直接

```bash
./gradlew :app:assembleRelease
```

也会在打包完成后自动追加加固。

#### 命令行参数（-P，优先级高于扩展配置，免改 build.gradle.kts）

```bash
./gradlew :app:selfReinforceApk \
  -PinputApk=app-release.apk -PoutputApk=out.apk \
  -Pks=keystore.jks -PksPass=xxx -Palias=xxx -PkeyPass=xxx \
  -PencryptedAssets=private/,config.bin \
  -Pchannels=oppo,xiaomi,huawei -PchannelsFile=channels.txt -PchannelOutputDir=out/channels \
  -PpgyerApiKey=xxx -PpgyerInstallType=2 -PpgyerInstallPassword=123456 -PpgyerUpdateDescription=自研加固 \
  -PpgyerUploadAllChannels=true \
  -PdingTalkWebhook=https://oapi.dingtalk.com/robot/send?access_token=xxx \
  -PdingTalkSecret=SECxxx -PdingTalkKeyword=DemoApp
```

| 参数 | 说明 |
|---|---|
| `inputApk` / `outputApk` | 输入/输出 APK（默认自动取 release 最新） |
| `ks/ksPass/alias/keyPass` | 重签名 keystore（不传则用 signingConfigs 或 debug 签名） |
| `encryptedAssets` | assets 加密规则（逗号分隔） |
| `channels` / `channelsFile` / `channelOutputDir` | 多渠道（与扩展配置合并去重） |
| `pgyerApiKey` 等 `pgyer*` | 蒲公英上传（配置 key 即启用） |
| `dingTalkWebhook` 等 `dingTalk*` | 钉钉群通知（配置 webhook 即启用） |

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
apply(plugin = "com.selfprotect.reinforce")
```

Groovy 写法：

```groovy
// 根 build.gradle
buildscript {
    repositories { maven { url 'https://jitpack.io' } }
    dependencies { classpath 'com.github.funfunfunnylsh:apk-self-reinforce-plugin:v1.0.0' }
}
apply plugin: 'com.selfprotect.reinforce'
```

然后同样配置 `selfReinforce { ... }` 扩展即可。版本号对应 GitHub tag（当前 `v1.0.0`）。

### assets 资源加密的业务接入

```java
// 原：context.getAssets().open("private/data.bin")
// 加密后必须走壳提供的透明解密 API：
InputStream in = com.selfprotect.SecureAssets.open(context, "private/data.bin");
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
├── src/main/kotlin/com/selfprotect/reinforce/
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

- 一代壳 + native 加固层：DEX 整体加密（native 解密、内存加载不落盘），未做方法级 VMP / 抽取。
- native 层为 C 实现（自写 AES/SHA256，零外部依赖），反调试/环境检测为常见特征库，对抗定制化对抗需持续迭代。
- 反调试后台线程与反模拟器/root 为**默认开启**，可通过 `ShellNative.init` 的 flags 按需关闭；真机误杀时用 `adb logcat -s SelfProtectNative` 查看命中原因。
- native 编译依赖本机 NDK（`sdk/ndk` 或 `ANDROID_NDK_HOME`）；缺失时自动跳过 so 注入并降级为 Java 层检测。

## Roadmap

- [x] 壳核心逻辑 native 化（解密/完整性/安全检测下沉 libselfprotect.so）
- [x] 载荷不落盘（API≥26 InMemoryDexClassLoader / API<26 memfd）
- [x] native 反调试 + 反模拟器/root
- [x] SO 字符串混淆（volatile XOR，防 clang 常量折叠）
- [ ] 关键方法轻量抽取（1-N 个敏感方法字节码抽到 native，运行时还原）
- [ ] 敏感方法接入 nmmvm 解释器（Apache 2.0）做 dex-vm 试点（详见 DEX/SO VMP 难度调研）

## License

[MIT](LICENSE)
