package fr.veripuce.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Générateur de candidats PACE et détection des paires aveugles au chiffre de contrôle.
 */
class MrzKeyCandidatesTest {

    @Test
    fun `l'original est toujours le premier candidat`() {
        assertEquals("X4RTBPFW4", MrzKeyCandidates.documentNumberCandidates("X4RTBPFW4").first())
    }

    @Test
    fun `chaque variante conserve le chiffre de controle ICAO`() {
        // Invariant fondateur : les substitutions choisies sont invisibles au checksum,
        // donc inutile de re-valider une variante avant de la tenter en PACE.
        for (doc in listOf("X4RTGPFW4", "AB1CD6QSL", "6L1SG8QCD", "123456789")) {
            val ref = MrzKeyCandidates.icaoCheckDigit(doc)
            for (variant in MrzKeyCandidates.documentNumberCandidates(doc, limit = 16)) {
                assertEquals("$doc -> $variant", ref, MrzKeyCandidates.icaoCheckDigit(variant))
            }
        }
    }

    @Test
    fun `le nombre de tentatives est borne`() {
        // « G » est une paire aveugle : sans borne, un numéro plein de G exploserait.
        val many = MrzKeyCandidates.documentNumberCandidates("GGGGGGGGG", limit = 4)
        assertEquals(4, many.size)
        assertTrue(many.toSet().size == many.size)  // pas de doublon
    }

    @Test
    fun `une lettre sans paire aveugle ne genere que l'original`() {
        assertEquals(listOf("XYZ"), MrzKeyCandidates.documentNumberCandidates("XYZ"))
    }

    @Test
    fun `substitution attendue pour G lu 6`() {
        // « X4RTGPFW4 » (G) doit produire « X4RT6PFW4 » (6) comme candidat.
        val cands = MrzKeyCandidates.documentNumberCandidates("X4RTGPFW4", limit = 16)
        assertTrue(cands.contains("X4RT6PFW4"))
    }

    @Test
    fun `differOnlyByBlindPairs - vrai pour une seule paire aveugle`() {
        assertTrue(MrzKeyCandidates.differOnlyByBlindPairs("X4RTGPFW4", "X4RT6PFW4"))  // G<->6
        assertTrue(MrzKeyCandidates.differOnlyByBlindPairs("AB1CD", "ABLCD"))          // 1<->L
    }

    @Test
    fun `differOnlyByBlindPairs - faux si difference hors paire aveugle`() {
        assertFalse(MrzKeyCandidates.differOnlyByBlindPairs("X4RTGPFW4", "X4RTAPFW4")) // G vs A
        assertFalse(MrzKeyCandidates.differOnlyByBlindPairs("ABC", "ABC"))             // identiques
        assertFalse(MrzKeyCandidates.differOnlyByBlindPairs("ABC", "ABCD"))            // longueurs
    }
}
