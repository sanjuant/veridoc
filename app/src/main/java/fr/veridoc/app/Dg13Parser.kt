package fr.veridoc.app

/**
 * Parser best-effort du DG13 de la CNI française.
 *
 * Le DG13 est propriétaire (non standardisé par l'ICAO). Sur le profil observé de la
 * CNI française, il contient un tag-list 0x5C puis des tags propriétaires, le tout
 * enveloppé dans le tag DG13 0x6D :
 *
 *   0x9F01 = taille (cm)          0x9F03 = adresse
 *   0x9F04 = complément/réservé   0x9F07 = lieu de naissance
 *
 * Porté depuis cnie-python-tools (`datagroups.py`), sémantique vérifiée sur échantillon.
 * Les libellés restent "observés/probables", pas des champs LDS universels.
 */
object Dg13Parser {

    private const val TAG_DG13 = 0x6D
    private const val TAG_TAGLIST = 0x5C
    private const val TAG_HEIGHT = 0x9F01
    private const val TAG_ADDRESS = 0x9F03
    private const val TAG_ADDRESS_EXTRA = 0x9F04
    private const val TAG_BIRTH_PLACE = 0x9F07

    fun parse(dg13Bytes: ByteArray): Dg13 {
        // Déballer l'enveloppe 0x6D si présente, sinon parser directement.
        val root = BerTlv.parse(dg13Bytes)
        val content = root.firstOrNull()?.takeIf { it.tag == TAG_DG13 }?.value ?: dg13Bytes

        var height: Int? = null
        var address: Dg13.Address? = null
        var birthPlace: Dg13.BirthPlace? = null
        var presentTags: List<String> = emptyList()
        val rawHex = LinkedHashMap<String, String>()

        for (node in BerTlv.parse(content)) {
            rawHex[formatTag(node.tag)] = node.value.toHexSpaced()
            when (node.tag) {
                TAG_TAGLIST ->
                    presentTags = BerTlv.parseTagList(node.value).map { formatTag(it) }
                TAG_HEIGHT ->
                    height = decodeCniText(node.value).toIntOrNull()
                TAG_ADDRESS ->
                    address = decodeAddress(node.value)
                TAG_BIRTH_PLACE ->
                    birthPlace = decodeBirthPlace(node.value)
                // TAG_ADDRESS_EXTRA et tout tag inconnu : conservés en brut (rawHex).
            }
        }

        return Dg13(
            heightCm = height,
            address = address,
            birthPlace = birthPlace,
            presentTags = presentTags,
            rawFieldsHex = rawHex,
        )
    }

    // Format observé : <rue<<code_postal<ville<code_pays<pays
    private fun decodeAddress(value: ByteArray): Dg13.Address {
        val p = decodeCniParts(value)
        return Dg13.Address(
            street = p.getOrNull(0),
            postalCode = p.getOrNull(1),
            city = p.getOrNull(2),
            countryCode = p.getOrNull(3),
            country = p.getOrNull(4),
            parts = p,
        )
    }

    private fun decodeBirthPlace(value: ByteArray): Dg13.BirthPlace {
        val p = decodeCniParts(value)
        return Dg13.BirthPlace(
            city = p.getOrNull(0),
            department = p.getOrNull(1),
            parts = p,
        )
    }

    /** Champs texte CNI : ASCII (octets hors ASCII remplacés), '<' séparateur/remplissage. */
    private fun decodeCniText(value: ByteArray): String =
        buildString {
            for (b in value) append(if (b >= 0) b.toInt().toChar() else '\uFFFD')
        }.trim('\u0000')

    private fun decodeCniParts(value: ByteArray): List<String> =
        decodeCniText(value).split('<').map { it.trim() }.filter { it.isNotEmpty() }

    private fun formatTag(tag: Int): String = tag.toString(16).uppercase()

    private fun ByteArray.toHexSpaced(): String =
        joinToString(" ") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
