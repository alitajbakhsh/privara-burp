// Privara iOS kit for Burp Suite: Gradle build (BApp Store criterion "Uses the Montoya API artifact").
//
//   ./gradlew jar      -> build/libs/privara-burp.jar
//   ./gradlew check    -> compile with -Werror, then run CoreTests and MontoyaSmoke (no Burp needed)
//
// The Montoya API is compileOnly: Burp provides it at run time, so it is never packed into the jar
// (the jar has no dependencies at all; the extension uses only the JDK and the Montoya API).
// Keep montoyaVersion in step with MONTOYA_VERSION in build.sh (the platform's QA checks it).

plugins {
    java
}

val montoyaVersion = "2025.5"
// One version string: the source's own Version.VERSION (build.sh stamps the same one).
val extVersion: String = Regex("""String VERSION = "([^"]+)"""")
    .find(file("src/main/java/com/privara/burp/core/Version.java").readText())!!
    .groupValues[1]

group = "com.privara"
version = extVersion

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testImplementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.encoding = "UTF-8"
}

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial", "-Werror"))
}

tasks.jar {
    archiveFileName.set("privara-burp.jar")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    manifest {
        attributes(
            "Implementation-Title" to "Privara iOS kit for Burp Suite",
            "Implementation-Version" to extVersion,
            "Implementation-Vendor" to "TAJ APPS LLC",
        )
    }
}

// The tests are plain main() programs (no test framework, so no extra dependency): the core with
// NO Burp API on the class path, then the Montoya side inside a recording fake of Burp.
val coreTests by tasks.registering(JavaExec::class) {
    description = "Core unit tests against a loopback stub of the Privara API (no Burp API on the class path)"
    classpath = sourceSets["main"].output + sourceSets["test"].output
    mainClass.set("com.privara.burp.core.CoreTests")
}

val montoyaSmoke by tasks.registering(JavaExec::class) {
    description = "The extension inside a recording fake of Burp (the real Montoya interfaces), headless"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.privara.burp.MontoyaSmoke")
    jvmArgs("-Djava.awt.headless=true")
}

tasks.named("check") {
    dependsOn(coreTests, montoyaSmoke)
}
