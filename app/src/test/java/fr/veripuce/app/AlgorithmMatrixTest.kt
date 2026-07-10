package fr.veripuce.app

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.jmrtd.lds.SODFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Matrice d'algorithmes de la passive authentication, sur PKI de test générée :
 * RSA PKCS#1 v1.5 (SHA-1/256/512), RSASSA-PSS, et ECDSA sur courbes NIST et
 * brainpool — celles des CSCA/DSC réels (les documents français utilisent
 * brainpool, que le provider par défaut d'Android ne connaît pas : le repli
 * BouncyCastle de la vérification de chaîne est exercé ici sur JVM, où SunEC
 * ne connaît pas non plus brainpool).
 */
class AlgorithmMatrixTest {

    private data class Combo(val digestAlg: String, val sigAlg: String, val keyGen: () -> KeyPair)

    private class Chain(val cscaKeys: KeyPair, val csca: java.security.cert.X509Certificate,
                        val dscKeys: KeyPair, val dsc: java.security.cert.X509Certificate)

    companion object {
        @JvmStatic
        @BeforeClass
        fun bc() {
            Security.addProvider(BouncyCastleProvider())
        }

        private fun rsa() = KeyPairGenerator.getInstance("RSA", "BC")
            .apply { initialize(2048) }.generateKeyPair()

        private fun ec(curve: String) = KeyPairGenerator.getInstance("EC", "BC")
            .apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
    }

    // RSASSA-PSS absent de la matrice : le générateur de SOD de JMRTD produit pour PSS
    // un SignerInfo que BouncyCastle refuse (quirk de génération). La couverture PSS
    // est assurée par le SOD PSS OFFICIEL du BSI 2013 (BsiReferenceDataTest), qui se
    // vérifie correctement — c'est la vérification qui compte pour l'application.
    private val combos = listOf(
        Combo("SHA-256", "SHA256withRSA") { rsa() },
        Combo("SHA-1", "SHA1withRSA") { rsa() },
        Combo("SHA-512", "SHA512withRSA") { rsa() },
        Combo("SHA-256", "SHA256withECDSA") { ec("secp256r1") },
        Combo("SHA-256", "SHA256withECDSA") { ec("brainpoolP256r1") },
        Combo("SHA-384", "SHA384withECDSA") { ec("brainpoolP384r1") },
    )

    private fun chain(combo: Combo): Chain {
        val cscaKeys = combo.keyGen()
        val dscKeys = combo.keyGen()
        val csca = certificate("CN=CSCA-TEST,C=UT", "CN=CSCA-TEST,C=UT", cscaKeys.public, cscaKeys.private, combo.sigAlg, isCa = true)
        val dsc = certificate("CN=DS-TEST,C=UT", "CN=CSCA-TEST,C=UT", dscKeys.public, cscaKeys.private, combo.sigAlg, isCa = false)
        return Chain(cscaKeys, csca, dscKeys, dsc)
    }

    private fun certificate(
        subject: String,
        issuer: String,
        publicKey: java.security.PublicKey,
        signingKey: java.security.PrivateKey,
        sigAlg: String,
        isCa: Boolean,
    ): java.security.cert.X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
            Date(1577836800000L), Date(2208988800000L), X500Name(subject), publicKey,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
        val signer = JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signingKey)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
    }

    private val dg1 = ByteArray(93) { it.toByte() }
    private val dg2 = ByteArray(2048) { (it * 3).toByte() }

    private fun sod(combo: Combo, chain: Chain): SODFile {
        val md = MessageDigest.getInstance(combo.digestAlg)
        // JMRTD exige de 2 à 16 empreintes dans un SOD. Provider « BC » explicite :
        // le provider JVM par défaut ne sait pas signer avec des clés brainpool.
        val hashes = mapOf(1 to md.digest(dg1), 2 to md.digest(dg2))
        return SODFile(combo.digestAlg, combo.sigAlg, hashes, chain.dscKeys.private, chain.dsc, "BC")
    }

    @Test
    fun `chaque combinaison d'algorithmes donne TRUSTED avec sa CSCA et une integrite OK`() {
        for (combo in combos) {
            val label = "${combo.digestAlg}/${combo.sigAlg}"
            val ch = chain(combo)
            val sod = sod(combo, ch)
            assertTrue("intégrité $label", PassiveAuth.verifyDataGroupHashes(sod, mapOf(1 to dg1, 2 to dg2)))
            assertEquals(
                "signature $label",
                SignatureCheck.TRUSTED,
                PassiveAuth.verifySodSignature(sod.encoded, sod, listOf(ch.csca)),
            )
        }
    }

    @Test
    fun `chaque combinaison reste VALID_UNTRUSTED sans magasin`() {
        for (combo in combos) {
            val ch = chain(combo)
            val sod = sod(combo, ch)
            assertEquals(
                "${combo.digestAlg}/${combo.sigAlg}",
                SignatureCheck.VALID_UNTRUSTED,
                PassiveAuth.verifySodSignature(sod.encoded, sod, emptyList()),
            )
        }
    }
}
