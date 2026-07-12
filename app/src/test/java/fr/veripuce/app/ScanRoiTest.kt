package fr.veripuce.app

import org.junit.Assert.assertTrue
import org.junit.Test

class ScanRoiTest {

    // Géométrie du mode MRZ (cf. ScanActivity).
    private fun mrz(w: Int, h: Int) = ScanRoi.mrzRoi(w, h, windowRatio = 4f, windowWidthFraction = 0.94f, windowVerticalBias = 0.42f)

    @Test
    fun `le recadrage reste dans les bornes de l'image`() {
        for ((w, h) in listOf(3024 to 4032, 1440 to 2560, 1080 to 1920, 720 to 1280)) {
            val r = mrz(w, h)
            assertTrue(r.left >= 0 && r.top >= 0 && r.right <= w && r.bottom <= h)
            assertTrue("dimensions positives", r.width > 0 && r.height > 0)
        }
    }

    @Test
    fun `le recadrage est bien plus petit que l'image entiere`() {
        val w = 3024; val h = 4032   // 12 Mpx redressé (cas terrain)
        val r = mrz(w, h)
        // La MRZ occupe ~toute la largeur mais une BANDE fine en hauteur : c'est le crop
        // vertical qui densifie (l'aire tombe à ~1/4, la hauteur à ~1/4).
        assertTrue("bande trop haute", r.height < h * 0.30)
        val ratioArea = r.width.toLong() * r.height / (w.toLong() * h).toDouble()
        assertTrue("ROI trop grande ($ratioArea)", ratioArea < 0.30)
    }

    @Test
    fun `la ROI est centree horizontalement et positionnee sur la MRZ`() {
        val w = 3024; val h = 4032
        val r = mrz(w, h)
        val cx = (r.left + r.right) / 2
        assertTrue("centrée en largeur", kotlin.math.abs(cx - w / 2) <= 2)
        // Fenêtre MRZ à 42 % de la hauteur : la ROI contient ce point.
        val yTarget = (h * 0.42f).toInt()
        assertTrue("contient la bande MRZ verticalement", yTarget in r.top..r.bottom)
    }

    @Test
    fun `la marge elargit la fenetre nominale`() {
        val w = 3024; val h = 4032
        val nominalW = w * 0.94f
        val r = mrz(w, h)
        assertTrue("la ROI est plus large que la fenêtre nominale (marge)", r.width > nominalW || r.width.toFloat() == w.toFloat())
    }

    @Test
    fun `image degeneree ne casse pas`() {
        val r = ScanRoi.mrzRoi(0, 0, 4f, 0.94f, 0.42f)
        assertTrue(r.width == 0 && r.height == 0)
    }
}
