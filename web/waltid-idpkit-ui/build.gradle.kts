import com.github.gradle.node.yarn.task.YarnTask

plugins {
    java
    id("com.github.node-gradle.node") version "3.4.0"
}

buildscript {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }

    dependencies {
        classpath("com.github.node-gradle:gradle-node-plugin:3.4.0")
    }
}

apply(plugin = "com.github.node-gradle.node")

/*
val buildTask = tasks.findByName("yarn_generate")!!.apply {
    dependsOn("yarn_install")
    inputs.dir("components")
    inputs.dir("pages")
    inputs.dir("layouts")
    inputs.dir("static")
    inputs.dir("store")
    inputs.file("nuxt.config.js")
    outputs.dir("dist")
}*/

val buildTask = tasks.register<YarnTask>("buildYarn") {
    dependsOn(tasks.npmInstall)
    yarnCommand.set(listOf("generate"))

    environment.set(mapOf("NODE_OPTIONS" to "--openssl-legacy-provider"))

    inputs.dir("components")
    inputs.dir("pages")
    inputs.dir("layouts")
    inputs.dir("static")
    inputs.dir("store")
    inputs.file("nuxt.config.js")
    outputs.dir("dist")
}


sourceSets {
    java {
        main {
            resources {
                srcDir(buildTask)
            }
        }
    }
}
