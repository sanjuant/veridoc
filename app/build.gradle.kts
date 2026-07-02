plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "fr.veridoc.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "fr.veridoc.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Les jars BouncyCastle (bcprov/bcutil) embarquent des métadonnées identiques
    // (OSGi, licences) qui entrent en collision au packaging de l'APK. On les écarte.
    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/*.SF",
                "META-INF/*.DSA",
                "META-INF/*.RSA",
            )
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("com.google.android.material:material:1.12.0")

    // Lecture eMRTD / eID (PACE, Secure Messaging, parsing des data groups, SOD)
    implementation("org.jmrtd:jmrtd:0.7.42")               // vérifier la dernière version
    implementation("net.sf.scuba:scuba-sc-android:0.0.26") // transport SCUBA pour Android

    // Crypto : courbes Brainpool, AES-CMAC… (voir le remplacement du provider BC au démarrage)
    // Aligné sur la variante que JMRTD tire en transitif (bcprov-jdk18on) pour éviter le
    // "Duplicate class" entre jdk15to18 et jdk18on. 1.78.1 écrase le 1.78 transitif.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Décodage JPEG 2000 de la photo (Android n'a pas javax.imageio)
    // Coordonnée d'origine "com.gemalto.jp2:jp2-android:1.0" introuvable (Maven/Google/JitPack).
    // Miroir Maven Central de JP2ForAndroid, même package com.gemalto.jp2.* + libs natives.
    implementation("io.github.CshtZrgk:jp2-android:1.0.0")
}
