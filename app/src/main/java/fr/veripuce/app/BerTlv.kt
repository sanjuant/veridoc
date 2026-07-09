package fr.veripuce.app

/**
 * Lecteur BER-TLV minimal. Port de `cnie/tlv.py` de cnie-python-tools :
 * tags multi-octets, longueurs en forme courte/longue, tolérance au padding final.
 */
data class Tlv(val tag: Int, val value: ByteArray)

object BerTlv {

    /** Lit un identifiant de tag BER à partir de [offset]. Retourne (tag, offsetSuivant). */
    fun readTag(data: ByteArray, offset: Int): Pair<Int, Int> {
        require(offset < data.size) { "Tag manquant" }
        var i = offset
        val first = data[i].toInt() and 0xFF
        i++
        var tag = first
        if (first and 0x1F == 0x1F) {
            while (true) {
                require(i < data.size) { "Tag multi-octets tronqué" }
                val b = data[i].toInt() and 0xFF
                i++
                tag = (tag shl 8) or b
                if (b and 0x80 == 0) break
            }
        }
        return tag to i
    }

    /** Lit une longueur BER (forme courte ou longue). Retourne (longueur, offsetSuivant). */
    fun readLen(data: ByteArray, offset: Int): Pair<Int, Int> {
        require(offset < data.size) { "Longueur manquante" }
        var i = offset
        val b = data[i].toInt() and 0xFF
        i++
        if (b < 0x80) return b to i
        val n = b and 0x7F
        require(n != 0) { "Longueur BER indéfinie non supportée" }
        require(i + n <= data.size) { "Longueur tronquée" }
        var len = 0
        repeat(n) { len = (len shl 8) or (data[i++].toInt() and 0xFF) }
        return len to i
    }

    private fun isTrailingPadding(data: ByteArray, from: Int): Boolean {
        if (from >= data.size) return false
        for (j in from until data.size) {
            val v = data[j].toInt() and 0xFF
            if (v != 0x00 && v != 0xFF) return false
        }
        return true
    }

    /** Découpe une séquence de TLV, en tolérant un éventuel padding final (0x00/0xFF). */
    fun parse(data: ByteArray, allowPadding: Boolean = true): List<Tlv> {
        val nodes = ArrayList<Tlv>()
        var i = 0
        while (i < data.size) {
            if (allowPadding && isTrailingPadding(data, i)) break
            val (tag, afterTag) = readTag(data, i)
            val (len, afterLen) = readLen(data, afterTag)
            val end = afterLen + len
            require(end <= data.size) {
                "TLV 0x${tag.toString(16)} déclare $len octets, buffer trop court"
            }
            nodes.add(Tlv(tag, data.copyOfRange(afterLen, end)))
            i = end
        }
        return nodes
    }

    /** Parse une suite d'identifiants de tags (valeur d'un tag-list 0x5C). */
    fun parseTagList(value: ByteArray): List<Int> {
        val tags = ArrayList<Int>()
        var i = 0
        while (i < value.size) {
            val (tag, next) = readTag(value, i)
            tags.add(tag)
            i = next
        }
        return tags
    }
}
