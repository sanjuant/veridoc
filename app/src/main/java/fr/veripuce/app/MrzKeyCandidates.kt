package fr.veripuce.app

/**
 * Candidats pour la clé PACE-MRZ, et confusions OCR que le chiffre de contrôle ICAO
 * ne peut PAS détecter.
 *
 * Le chiffre de contrôle (pondération 7-3-1) est aveugle à toute substitution
 * lettre↔chiffre dont l'écart de valeur est un multiple de 10 : 7·10 ≡ 3·10 ≡ 1·10 ≡ 0
 * (mod 10). Parmi ces paires, les glyphes que ML Kit (modèle latin générique, non
 * entraîné sur la police OCR-B) confond de façon plausible : G/6, L/1, Q/6, S/8, C/2,
 * D/3. Une telle erreur passe donc [MrzOcr] `checkOk` sans être vue, produit une clé
 * PACE fausse (avalanche SHA-1) → SW 6300 au General Authenticate. On retente alors
 * PACE avec les variantes du numéro (une position permutée à la fois), bornées.
 */
object MrzKeyCandidates {

    /** Substitutions invisibles au chiffre de contrôle ICAO (paires « aveugles »). */
    val BLIND_SUBSTITUTIONS: Map<Char, List<Char>> = mapOf(
        'G' to listOf('6'),
        '6' to listOf('G', 'Q'),
        'Q' to listOf('6'),
        'L' to listOf('1'),
        '1' to listOf('L'),
        'S' to listOf('8'),
        '8' to listOf('S'),
        'C' to listOf('2'),
        '2' to listOf('C'),
        'D' to listOf('3'),
        '3' to listOf('D'),
    )

    /**
     * Le numéro tel que lu, puis des variantes par UNE substitution de paire aveugle,
     * bornées à [limit] essais au total (chaque essai = une session PACE ≈ 1 s). Toutes
     * les variantes conservent le chiffre de contrôle ICAO (cf. [icaoCheckDigit]) — donc
     * inutile de re-valider. Ordre déterministe : gauche→droite, l'original en premier.
     */
    fun documentNumberCandidates(documentNumber: String, limit: Int = 4): List<String> {
        val out = LinkedHashSet<String>()
        out += documentNumber
        outer@ for (i in documentNumber.indices) {
            for (sub in BLIND_SUBSTITUTIONS[documentNumber[i]].orEmpty()) {
                out += documentNumber.substring(0, i) + sub + documentNumber.substring(i + 1)
                if (out.size >= limit) break@outer
            }
        }
        return out.toList()
    }

    /** Chiffre de contrôle ICAO 9303 (0-9=valeur, A-Z=10..35, '<' et autres=0 ; 7-3-1). */
    fun icaoCheckDigit(field: String): Int {
        val weights = intArrayOf(7, 3, 1)
        var sum = 0
        field.forEachIndexed { i, c ->
            val v = when (c) {
                in '0'..'9' -> c - '0'
                in 'A'..'Z' -> c - 'A' + 10
                else -> 0
            }
            sum += v * weights[i % 3]
        }
        return sum % 10
    }

    /**
     * Deux numéros de même longueur ne diffèrent QUE sur des positions en paire aveugle
     * (aucune autre différence) → l'OCR ne peut pas les départager, ce sont deux
     * candidats PACE légitimes à essayer plutôt que d'en élire un au hasard.
     */
    fun differOnlyByBlindPairs(a: String, b: String): Boolean {
        if (a.length != b.length || a == b) return false
        for (i in a.indices) {
            if (a[i] == b[i]) continue
            if (BLIND_SUBSTITUTIONS[a[i]]?.contains(b[i]) != true) return false
        }
        return true
    }
}
