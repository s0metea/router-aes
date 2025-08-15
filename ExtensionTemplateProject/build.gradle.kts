plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}

tasks.test {
    useJUnitPlatform()
}

java {
    // Use the system JDK; adjust if a specific toolchain is required
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(listOf("src/main/java", "../interfaces"))
        }
        resources {
            setSrcDirs(listOf("src/main/resources"))
        }
    }
    val test by getting {
        java {
            setSrcDirs(listOf("src/test/java"))
        }
        resources {
            setSrcDirs(listOf("src/test/resources"))
        }
    }
}
