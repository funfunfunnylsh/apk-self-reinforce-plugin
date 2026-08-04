package com.selfprotect.reinforce

import org.gradle.api.internal.TaskInternal
import org.gradle.testfixtures.ProjectBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 打包阶段集成回归测试：
 *  - selfReinforceApk 自动依赖 assembleRelease（一条命令全链路）
 *  - hookToAssembleRelease=true 时 assembleRelease.finalizedBy(selfReinforceApk)
 */
class SelfReinforcePluginTest {

    private fun newProject(withAssembleRelease: Boolean = false): org.gradle.api.Project {
        val project = ProjectBuilder.builder().build()
        if (withAssembleRelease) {
            project.tasks.register("assembleRelease")
        }
        return project
    }

    private fun taskDeps(task: org.gradle.api.Task): List<String> =
        (task as TaskInternal).taskDependencies.getDependencies(task).map { it.name }

    @Test
    fun `apply 后注册 selfReinforceApk 任务`() {
        val project = newProject()
        project.pluginManager.apply("com.selfprotect.reinforce")
        val task = project.tasks.findByName("selfReinforceApk")
        assertTrue("应注册 selfReinforceApk 任务", task != null)
    }

    @Test
    fun `selfReinforceApk 默认依赖 assembleRelease`() {
        val project = newProject(withAssembleRelease = true)
        project.pluginManager.apply("com.selfprotect.reinforce")
        val task = project.tasks.findByName("selfReinforceApk")!!
        assertTrue("应依赖 assembleRelease", taskDeps(task).contains("assembleRelease"))
    }

    @Test
    fun `无 assembleRelease 时依赖为空不报错`() {
        // 非 Android 工程（或 AGP 未注册该任务）时 dependsOn 应为空集合，不抛异常
        val project = newProject(withAssembleRelease = false)
        project.pluginManager.apply("com.selfprotect.reinforce")
        val task = project.tasks.findByName("selfReinforceApk")!!
        assertTrue("无 assembleRelease 时依赖应为空", taskDeps(task).isEmpty())
    }

    /** 触发 afterEvaluate（Project.evaluate 为 internal API） */
    private fun evaluate(project: org.gradle.api.Project) {
        (project as org.gradle.api.internal.project.ProjectInternal).evaluate()
    }

    @Test
    fun `hookToAssembleRelease 开启后 assembleRelease finalize selfReinforceApk`() {
        val project = newProject(withAssembleRelease = true)
        project.pluginManager.apply("com.selfprotect.reinforce")
        val ext = project.extensions.findByName("selfReinforce") as SelfReinforceExtension
        ext.hookToAssembleRelease.set(true)
        evaluate(project)
        val assemble = project.tasks.findByName("assembleRelease")!!
        val finalizedBy = (assemble as TaskInternal).finalizedBy.getDependencies(assemble).map { it.name }
        assertTrue("assembleRelease 应 finalize selfReinforceApk", finalizedBy.contains("selfReinforceApk"))
    }

    @Test
    fun `默认 hookToAssembleRelease 为 false`() {
        val project = newProject(withAssembleRelease = true)
        project.pluginManager.apply("com.selfprotect.reinforce")
        evaluate(project)
        val assemble = project.tasks.findByName("assembleRelease")!!
        val finalizedBy = (assemble as TaskInternal).finalizedBy.getDependencies(assemble).map { it.name }
        assertTrue("默认不应 finalize selfReinforceApk", finalizedBy.isEmpty())
    }

    @Test
    fun `extension 默认值检查`() {
        val project = newProject()
        project.pluginManager.apply("com.selfprotect.reinforce")
        val ext = project.extensions.findByName("selfReinforce") as SelfReinforceExtension
        assertEquals(false, ext.hookToAssembleRelease.getOrElse(false))
    }
}
