package fr.veripuce.app

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jmrtd.lds.SODFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security

/**
 * Interopérabilité sur les algorithmes ANCIENS, avec les fixtures historiques des
 * tests de JMRTD (données de test publiques, DSC de TEST embarqués) :
 *
 * - bsi2008  : ECDSA-with-SHA1 + empreintes SHA-1 (jeu de référence BSI 2008) ;
 * - loes2006 : SHA-256 + RSA PKCS#1 v1.5 (passeport de test néerlandais « Loes »).
 *
 * Complète le jeu BSI 2013 (RSASSA-PSS) et la matrice générée (AlgorithmMatrixTest).
 */
class LegacyReferenceDataTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun bc() {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private fun res(name: String): ByteArray =
        javaClass.getResourceAsStream("/$name")!!.readBytes()

    // ---- BSI 2008 : ECDSA / SHA-1 ----

    private val bsiSodBytes by lazy { res("bsi2008/EF_SOD.bin") }
    private val bsiSod by lazy { SODFile(bsiSodBytes.inputStream()) }

    @Test
    fun `bsi2008 - SOD ECDSA-SHA1 parse, empreintes SHA-1`() {
        assertEquals("SHA-1", bsiSod.digestAlgorithm)
        assertTrue(bsiSod.digestEncryptionAlgorithm.contains("ECDSA", ignoreCase = true))
    }

    @Test
    fun `bsi2008 - integrite SHA-1 des DG officiels`() {
        val ok = PassiveAuth.verifyDataGroupHashes(
            bsiSod,
            mapOf(
                1 to res("bsi2008/Datagroup1.bin"),
                2 to res("bsi2008/Datagroup2.bin"),
                14 to res("bsi2008/Datagroup14.bin"),
            ),
        )
        assertTrue(ok)
    }

    @Test
    fun `bsi2008 - le DG15 du jeu ne correspond pas (cas negatif reel)`() {
        assertFalse(
            PassiveAuth.verifyDataGroupHashes(bsiSod, mapOf(15 to res("bsi2008/Datagroup15.bin"))),
        )
    }

    @Test
    fun `bsi2008 - signature ECDSA verifiee, autorite de test non reconnue`() {
        assertEquals(
            SignatureCheck.VALID_UNTRUSTED,
            PassiveAuth.verifySodSignature(bsiSodBytes, bsiSod, emptyList()),
        )
    }

    // ---- Loes 2006 : RSA PKCS#1 v1.5 / SHA-256 ----

    private val loesSodBytes by lazy { res("loes2006/EF_SOD.bin") }
    private val loesSod by lazy { SODFile(loesSodBytes.inputStream()) }

    @Test
    fun `loes2006 - SOD RSA v1_5 parse, DSC de test neerlandais`() {
        assertEquals("SHA-256", loesSod.digestAlgorithm)
        assertTrue(loesSod.docSigningCertificate.subjectX500Principal.name.contains("Test"))
    }

    @Test
    fun `loes2006 - integrite complete DG1+DG2+DG15`() {
        val ok = PassiveAuth.verifyDataGroupHashes(
            loesSod,
            mapOf(
                1 to res("loes2006/Datagroup1.bin"),
                2 to res("loes2006/Datagroup2.bin"),
                15 to res("loes2006/Datagroup15.bin"),
            ),
        )
        assertTrue(ok)
    }

    @Test
    fun `loes2006 - un DG2 altere est detecte`() {
        val dg2 = res("loes2006/Datagroup2.bin").also { it[1000] = (it[1000] + 1).toByte() }
        assertFalse(PassiveAuth.verifyDataGroupHashes(loesSod, mapOf(2 to dg2)))
    }

    @Test
    fun `loes2006 - signature RSA v1_5 verifiee, autorite de test non reconnue`() {
        assertEquals(
            SignatureCheck.VALID_UNTRUSTED,
            PassiveAuth.verifySodSignature(loesSodBytes, loesSod, emptyList()),
        )
    }
}
