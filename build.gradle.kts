plugins {
    kotlin("jvm") version "1.5.31"
    application
    `maven-publish`
}

group = "id.walt"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://jitpack.io")
    maven("https://maven.walt.id/repository/waltid/")
    maven("https://maven.walt.id/repository/waltid-ssi-kit/")

    maven("https://maven.walt.id/repository/danubetech")

    mavenLocal()
    maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("io.javalin:javalin-bundle:4.3.0")
    implementation("com.github.kmehrunes:javalin-jwt:0.3")
    implementation("com.beust:klaxon:5.5")
    implementation("com.nimbusds:oauth2-oidc-sdk:9.27")
    // CLI
    implementation("com.github.ajalt.clikt:clikt-jvm:3.4.0")
    implementation("com.github.ajalt.clikt:clikt:3.4.0")
    // SSIKIT
    implementation("id.walt:waltid-ssi-kit:1.11.0-SNAPSHOT")
    implementation("id.walt:waltid-ssikit-vclib:1.22.0")
    implementation("id.walt:waltid-walletkit:1.0-SNAPSHOT")

    // Service-Matrix
    implementation("id.walt.servicematrix:WaltID-ServiceMatrix:1.1.0")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.0-alpha6")
    implementation("org.slf4j:slf4j-simple:2.0.0-alpha6")
    implementation("io.github.microutils:kotlin-logging-jvm:2.1.21")

    //JSON
    implementation("com.jayway.jsonpath:json-path:2.7.0")

    // Testing
    //testImplementation(kotlin("test-junit"))
    testImplementation("io.mockk:mockk:1.12.2")

    testImplementation("io.kotest:kotest-runner-junit5:5.1.0")
    testImplementation("io.kotest:kotest-assertions-core:5.1.0")
    testImplementation("io.kotest:kotest-assertions-json:5.1.0")

    // NftKit
    implementation("id.walt:waltid-nftkit:1.0.0")

    // Web UI
    implementation(project(":web:waltid-idpkit-ui"))
}


tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions.jvmTarget = "16"
}

tasks.withType<Test> {
    useJUnitPlatform()
}

application {
    mainClass.set("id.walt.idp.MainKt")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("walt.id IDP Kit")
                description.set("Kotlin/Java library for IDP Kit.")
                url.set("https://walt.id")
            }
            from(components["java"])
        }
    }

    repositories {
        maven {
            url = uri("https://maven.walt.id/repository/waltid-ssi-kit/")
            val usernameFile = File("secret_maven_username.txt")
            val passwordFile = File("secret_maven_password.txt")
            val secretMavenUsername = System.getenv()["MAVEN_USERNAME"] ?: if (usernameFile.isFile) { usernameFile.readLines()[0] } else { "" }
            println("Deploy username length: ${secretMavenUsername.length}")
            val secretMavenPassword = System.getenv()["MAVEN_PASSWORD"] ?: if (passwordFile.isFile) { passwordFile.readLines()[0] } else { "" }

            if (secretMavenPassword.isBlank()) {
                println("WARNING: Password is blank!")
            }

            credentials {
                username = secretMavenUsername
                password = secretMavenPassword
            }
        }
    }
}
