package fr.veripuce.app

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.cert.X509Certificate

/**
 * Garde-fou sur le magasin CSCA embarqué (`assets/csca/`), via la logique de production
 * [CscaStore.parse] : le bundle doit fournir des certificats exploitables (certaines CSCA
 * utilisent des paramètres EC explicites que seul BouncyCastle sait lire) et contenir les
 * CSCA françaises — sans elles, aucun document français ne peut être « émis par l'État ».
 */
class CscaBundleTest {

    private fun cscaDir(): File {
        // Les tests unitaires s'exécutent avec app/ comme répertoire de travail.
        val fromApp = File("src/main/assets/csca")
        return if (fromApp.isDirectory) fromApp else File("app/src/main/assets/csca")
    }

    private fun loadAll(): List<X509Certificate> {
        val exts = setOf("cer", "der", "crt", "pem")
        return cscaDir().listFiles().orEmpty()
            .filter { it.extension.lowercase() in exts }
            .flatMap { CscaStore.parse(it.readBytes()) }
    }

    @Test
    fun `le bundle CSCA se charge avec une perte quasi nulle`() {
        val certs = loadAll()
        // Le bundle déposé contient ~770 certificats ; si le parsing en perd plus de
        // quelques-uns, un provider ou une regex a régressé.
        assertTrue("Seulement ${certs.size} certificats CSCA chargés (>= 700 attendus)", certs.size >= 700)
    }

    @Test
    fun `le bundle contient les CSCA francaises passeport et eID`() {
        val frNames = loadAll()
            .map { it.subjectX500Principal.name }
            .filter { it.contains("C=FR") }
        assertTrue("Aucune CSCA-FRANCE dans le bundle", frNames.any { it.contains("CSCA-FRANCE") })
        assertTrue("Pas de CSCA eID-FRANCE (CNIe) dans le bundle", frNames.any { it.contains("eID-FRANCE") })
    }

    @Test
    fun `les CSCA francaises sont des CA (basicConstraints)`() {
        // Limité aux FR : de vieilles CSCA étrangères peuvent omettre l'extension
        // basicConstraints, mais les CSCA françaises la portent toujours (CA:TRUE).
        val fr = loadAll().filter { it.subjectX500Principal.name.contains("C=FR") }
        val nonCa = fr.filter { it.basicConstraints == -1 }
        assertTrue(
            "CSCA françaises non-CA : ${nonCa.map { it.subjectX500Principal.name }}",
            nonCa.isEmpty(),
        )
    }
}
