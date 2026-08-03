plugins {
    `java-library`
    `kotlin-dsl`
    `java-gradle-plugin`
    `maven-publish`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.0")
}

// 自研 APK 加固插件：DEX 加密 + 壳 Application + Manifest 二进制改写 + 重签名
gradlePlugin {
    plugins {
        create("selfReinforcePlugin") {
            id = "com.cdtec.plugin.apk-self-reinforce"
            implementationClass = "com.cdtec.selfreinforce.SelfReinforcePlugin"
        }
    }
}

// 命令行直跑入口（无需接入业务工程即可验证加固流水线）：
// ./gradlew :apk-self-reinforce-plugin:selfReinforceCli -PinputApk=... -PoutputApk=... [-Pks=... -PksPass=... -Palias=... -PkeyPass=...]
tasks.register<JavaExec>("selfReinforceCli") {
    group = "reinforce"
    mainClass.set("com.cdtec.selfreinforce.ReinforceCliKt")
    classpath = sourceSets["main"].runtimeClasspath
    val props = listOf("inputApk", "outputApk", "sdkDir", "ks", "ksPass", "alias", "keyPass", "encryptedAssets")
        .mapNotNull { k -> project.findProperty(k)?.let { "$k=$it" } }
    args = props
}

tasks.register<Jar>("sourceJar") {
    from(sourceSets.getByName("main").allSource)
    archiveClassifier.set("sources")
}
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("apkSelfReinforcePlugin") {
                from(components["java"])
                groupId = "com.cdtec.plugin"
                artifactId = "apk-self-reinforce"
                version = "1.0.0"
                artifact(tasks["sourceJar"])
            }
        }
    }
}
