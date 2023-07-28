import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.6.0"
    id("com.diffplug.spotless") version "5.12.1"
}

repositories {
    mavenCentral()
}

description = "Custom scripts that will be used with Astra Security's Scanner microservice."
val scriptsDir = layout.buildDirectory.dir("scripts")

zapAddOn {
    addOnId.set("astraScripts")
    addOnName.set("Astra Scripts")
    zapVersion.set("2.10.0")
    addOnStatus.set(AddOnStatus.RELEASE)

    releaseLink.set("https://tijori.getastra.com/astra/vapt/scanner-rules/-/releases/v@CURRENT_VERSION@")
    unreleasedLink.set("https://tijori.getastra.com/astra/vapt/scanner-rules/-/compare/v@CURRENT_VERSION@...master")

    manifest {
        author.set("Astra Security")
        url.set("https://www.getastra.com/")
        repo.set("https://tijori.getastra.com/astra/vapt/scanner-rules/")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        files.from(scriptsDir)
        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

val jupiterVersion = "5.7.0-M1"

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs = listOf("-Xlint:all", "-Xlint:-options", "-Werror")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

val copyScriptsTask by tasks.creating(DefaultTask::class) {
    val bruh = File("scripts").walk().filter {
        it.isFile()
    }.forEach {
        val scriptName = it.getName()
        if (scriptName != ".DS_Store") {
            val scriptType = scriptName.substring(scriptName.lastIndexOf('.', scriptName.length - 4) + 1, scriptName.lastIndexOf('.'))
            copy {
                from(it)
                into(scriptsDir.get().dir(project.name).dir(scriptType))
            }
        }
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation("commons-io:commons-io:2.6")
    implementation("org.apache.commons:commons-csv:1.8")
    implementation("org.apache.commons:commons-text:1.10.0")
    implementation("org.apache.commons:commons-collections4:4.4")
    implementation("com.google.re2j:re2j:1.6")
    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("com.shapesecurity:salvation2:3.0.0")
}

sourceSets["main"].output.dir(mapOf("builtBy" to copyScriptsTask), scriptsDir)

spotless {
    kotlinGradle {
        ktlint()
    }

    java {
        googleJavaFormat("1.7").aosp()
    }
}
