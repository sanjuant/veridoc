package fr.veridoc.app

import android.graphics.Bitmap

/**
 * Résultat d'une lecture de CNIe.
 *
 * Les deux booléens de vérification sont ce qui distingue une simple lecture d'une
 * vérification anti-fraude : [hashesMatchSod] atteste que les données ne sont pas
 * altérées, [sodSignatureVerified] que la carte a bien été émise par l'État.
 */
data class ReadResult(
    val mrz: String,
    val documentNumber: String,
    val surname: String,
    val givenNames: String,
    val dateOfBirth: String,
    val nationality: String,
    val photo: Bitmap?,
    val dg13: Dg13?,
    val hashesMatchSod: Boolean,
    val sodSignatureVerified: Boolean,
)
