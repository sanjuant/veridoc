package fr.veridoc.app

/**
 * Données extraites du DG13 de la CNI française (spécifique France, non standard ICAO).
 *
 * Les libellés sont "observés/probables" : le DG13 est propriétaire, ces champs ne sont
 * pas des champs LDS universels. En cas de doute, [rawFieldsHex] conserve le brut.
 */
data class Dg13(
    val heightCm: Int? = null,
    val address: Address? = null,
    val birthPlace: BirthPlace? = null,
    val presentTags: List<String> = emptyList(),
    val rawFieldsHex: Map<String, String> = emptyMap(),
) {
    /** Format observé : rue, code postal, ville, code pays, pays. */
    data class Address(
        val street: String? = null,
        val postalCode: String? = null,
        val city: String? = null,
        val countryCode: String? = null,
        val country: String? = null,
        val parts: List<String> = emptyList(),
    )

    data class BirthPlace(
        val city: String? = null,
        val department: String? = null,
        val parts: List<String> = emptyList(),
    )
}
