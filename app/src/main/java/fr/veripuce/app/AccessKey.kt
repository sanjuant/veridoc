package fr.veripuce.app

/**
 * Clé d'accès à la puce eMRTD (ICAO 9303).
 *
 * - [Can] : carte d'identité française. Ouverture par PACE-CAN (les 6 chiffres du recto).
 * - [Mrz] : passeport (et CNIe si on préfère). Clé dérivée de la MRZ — n° document,
 *   date de naissance et date d'expiration (AAMMJJ) — utilisée en PACE-MRZ ou, à défaut,
 *   en BAC sur les documents plus anciens.
 *
 * DG1/DG2/EF.SOD se lisent ensuite de façon identique quel que soit le mode ; seul le
 * DG13 (propriétaire France) n'existe que sur la CNIe.
 */
sealed class AccessKey {
    data class Can(val can: String) : AccessKey()

    data class Mrz(
        val documentNumber: String,
        val dateOfBirth: String,   // AAMMJJ
        val dateOfExpiry: String,  // AAMMJJ
    ) : AccessKey()
}
