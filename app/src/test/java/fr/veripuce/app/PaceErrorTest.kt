package fr.veripuce.app

import android.nfc.TagLostException
import net.sf.scuba.smartcards.CardServiceException
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Classification refus de clé (SW 6300/63Cx) vs aléa transitoire. C'est ce qui décide
 * si l'UI propose le CAN (refus) ou invite à re-présenter la carte (transitoire).
 */
class PaceErrorTest {

    @Test
    fun `SW 6300 est un refus de cle`() {
        assertTrue(PaceError.isKeyRefused(CardServiceException("auth failed", 0x6300)))
    }

    @Test
    fun `SW 63C2 (compteur d'essais) est un refus de cle`() {
        assertTrue(PaceError.isKeyRefused(CardServiceException("wrong, 2 tries left", 0x63C2)))
    }

    @Test
    fun `refus detecte meme enfoui dans la chaine de causes`() {
        val wrapped = RuntimeException("PACE", CardServiceException("GA", 0x6300))
        assertTrue(PaceError.isKeyRefused(wrapped))
    }

    @Test
    fun `TagLost n'est pas un refus de cle`() {
        val e = TagLostException("tag lost")
        assertFalse(PaceError.isKeyRefused(e))
        assertTrue(PaceError.isTagLost(e))
    }

    @Test
    fun `IOException n'est pas un refus de cle`() {
        assertFalse(PaceError.isKeyRefused(IOException("timeout")))
    }

    @Test
    fun `une exception CardService sans SW de refus n'est pas un refus`() {
        // 6A80/6A88 = rejet de protocole (MSE:Set AT), pas un mauvais mot de passe.
        assertFalse(PaceError.isKeyRefused(CardServiceException("wrong data", 0x6A80)))
        assertFalse(PaceError.isKeyRefused(CardServiceException("no SW")))
    }
}
