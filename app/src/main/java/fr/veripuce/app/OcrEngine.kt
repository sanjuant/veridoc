package fr.veripuce.app

import android.graphics.Bitmap

/**
 * Abstraction du moteur de reconnaissance de texte utilisé pour lire la MRZ (ou le CAN).
 *
 * Objectif : rendre le moteur INTERCHANGEABLE. Historiquement c'était ML Kit (recognizer
 * latin générique) ; on passe à Tesseract piloté par un modèle OCR-B dédié, qui lit
 * correctement la police des MRZ là où le modèle générique produisait de gros ratés
 * (état « FRA » lu « LEF », numéro tout en lettres). L'interface permet de basculer d'un
 * moteur à l'autre — ou de les combiner en vote — sans toucher au pipeline en aval
 * ([MrzOcr] / [MrzVote] / [MrzKeyCandidates]), qui reste 100 % `String`.
 *
 * L'implémentation est appelée depuis le thread d'analyse caméra (mono-thread) de
 * [ScanActivity] : [recognize] est SYNCHRONE et peut être coûteuse.
 */
interface OcrEngine {

    /**
     * Reconnaît le texte de [bitmap] (le crop MRZ déjà redressé et prétraité).
     * Renvoie le texte brut (lignes séparées par des retours), ou `null` si rien de lisible.
     * Ne recycle pas [bitmap] (l'appelant en reste propriétaire).
     */
    fun recognize(bitmap: Bitmap): String?

    /** Libère les ressources natives. Après appel, l'instance n'est plus utilisable. */
    fun close()
}
