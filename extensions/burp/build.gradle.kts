plugins {
    java
}

group = "com.indago"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API 2025.12
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.12")

    // JSON parsing
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks.jar {
    // Include all dependencies in the JAR for Burp
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })

    manifest {
        attributes(
            "Implementation-Title" to "Indago Burp Extension",
            "Implementation-Version" to version
        )
    }

    archiveBaseName.set("indago-burp-extension")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
