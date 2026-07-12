package fr.veripuce.app

import kotlin.math.roundToInt

/** Rectangle de recadrage (pixels), pur/testable — pas d'`android.graphics.Rect`. */
data class RoiRect(val left: Int, val top: Int, val right: Int, val bottom: Int) {
    val width: Int get() = right - left
    val height: Int get() = bottom - top
}

/**
 * Zone d'intérêt (ROI) à recadrer AVANT l'OCR : la fenêtre MRZ, au lieu de la trame
 * entière (souvent 12 Mpx). Recadrer densifie énormément les caractères OCR-B et
 * fiabilise ML Kit (le modèle latin générique lit mal une petite MRZ noyée dans une
 * grande image).
 *
 * La fenêtre du viseur est définie en fractions de la VUE ; on l'applique ici à l'image
 * REDRESSÉE (mêmes fractions), avec une [margin] généreuse pour absorber l'écart
 * d'échelle preview↔capteur (FILL_CENTER) — on sur-couvre plutôt que de rogner la MRZ.
 */
object ScanRoi {

    fun mrzRoi(
        width: Int,
        height: Int,
        windowRatio: Float,
        windowWidthFraction: Float,
        windowVerticalBias: Float,
        margin: Float = 0.22f,
    ): RoiRect {
        if (width <= 0 || height <= 0) return RoiRect(0, 0, width.coerceAtLeast(0), height.coerceAtLeast(0))

        val winW = width * windowWidthFraction
        val winH = (winW / windowRatio).coerceAtMost(height * 0.68f) // même plafond que le viseur

        val cropW = (winW * (1f + 2f * margin)).coerceIn(1f, width.toFloat())
        val cropH = (winH * (1f + 2f * margin)).coerceIn(1f, height.toFloat())

        val cx = width / 2f
        val cy = height * windowVerticalBias
        val left = (cx - cropW / 2f).coerceIn(0f, width - cropW)
        val top = (cy - cropH / 2f).coerceIn(0f, height - cropH)

        return RoiRect(
            left = left.roundToInt(),
            top = top.roundToInt(),
            right = (left + cropW).roundToInt(),
            bottom = (top + cropH).roundToInt(),
        )
    }
}
