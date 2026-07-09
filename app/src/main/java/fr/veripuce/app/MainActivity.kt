package fr.veripuce.app

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.ColorRes
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.imageview.ShapeableImageView
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.Security

/**
 * Flux unique : scanner la MRZ -> le type de document est déduit -> lecture de la puce.
 * Le CAN de la CNIe (recto) reste demandé (il ne figure pas dans la MRZ) ; la MRZ scannée
 * sert alors à vérifier que la puce correspond au document.
 */
class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var readJob: Job? = null

    /** MRZ scannée (ou saisie) : détermine le type de document et sert de référence de cohérence. */
    private var scanned: MrzOcr.MrzData? = null

    /** Statut posé par le retour de scan : ne pas l'écraser au onResume qui suit. */
    private var statusSetByScan = false

    private lateinit var scanMrz: MaterialButton
    private lateinit var manualToggle: MaterialButton
    private lateinit var manualGroup: View
    private lateinit var docInput: TextInputEditText
    private lateinit var dobInput: TextInputEditText
    private lateinit var expInput: TextInputEditText
    private lateinit var manualCan: TextInputEditText

    private lateinit var detectedCard: MaterialCardView
    private lateinit var detectedType: TextView
    private lateinit var detectedFields: TextView
    private lateinit var chipMrzValid: Chip
    private lateinit var canGroup: View
    private lateinit var canInput: TextInputEditText

    private lateinit var status: TextView
    private lateinit var statusIcon: ImageView
    private lateinit var progress: CircularProgressIndicator

    private lateinit var resultCard: MaterialCardView
    private lateinit var photo: ShapeableImageView
    private lateinit var nameView: TextView
    private lateinit var fields: TextView
    private lateinit var extra: TextView
    private lateinit var chipIntegrity: Chip
    private lateinit var chipConsistency: Chip
    private lateinit var chipClone: Chip
    private lateinit var chipSignature: Chip

    /** Retour du scan OCR : MRZ -> détection ; CAN -> pré-remplit le champ CAN. */
    private val scanLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            val data = res.data ?: return@registerForActivityResult
            when {
                res.resultCode == RESULT_OK && data.getStringExtra(ScanActivity.EXTRA_MODE) == ScanActivity.MODE_MRZ ->
                    onMrzScanned(
                        MrzOcr.MrzData(
                            documentNumber = data.getStringExtra(ScanActivity.EXTRA_DOC).orEmpty(),
                            dateOfBirth = data.getStringExtra(ScanActivity.EXTRA_DOB).orEmpty(),
                            dateOfExpiry = data.getStringExtra(ScanActivity.EXTRA_EXP).orEmpty(),
                            docType = runCatching {
                                MrzOcr.DocType.valueOf(data.getStringExtra(ScanActivity.EXTRA_DOCTYPE).orEmpty())
                            }.getOrDefault(MrzOcr.DocType.PASSPORT),
                            issuingState = data.getStringExtra(ScanActivity.EXTRA_STATE).orEmpty(),
                        )
                    )

                res.resultCode == RESULT_OK && data.getStringExtra(ScanActivity.EXTRA_MODE) == ScanActivity.MODE_CAN -> {
                    canInput.setText(data.getStringExtra(ScanActivity.EXTRA_CAN))
                    setStatus(getString(R.string.scan_filled), R.drawable.ic_state_ok, R.color.on_ok_container)
                    statusSetByScan = true
                }

                data.getBooleanExtra(ScanActivity.EXTRA_MANUAL_REQUESTED, false) -> {
                    // Repli demandé depuis le scanner (basse lumière, MRZ illisible…).
                    manualGroup.visibility = View.VISIBLE
                    docInput.requestFocus()
                    setStatus(getString(R.string.scan_first), R.drawable.ic_state_info, R.color.on_neutral_container)
                    statusSetByScan = true
                }

                data.getBooleanExtra(ScanActivity.EXTRA_CAMERA_UNAVAILABLE, false) -> {
                    warn(getString(R.string.camera_unavailable)); statusSetByScan = true
                    manualGroup.visibility = View.VISIBLE
                }

                data.getBooleanExtra(ScanActivity.EXTRA_PERMISSION_DENIED, false) -> {
                    val blocked = data.getBooleanExtra(ScanActivity.EXTRA_PERMISSION_PERMANENT, false)
                    warn(getString(if (blocked) R.string.camera_blocked else R.string.camera_denied))
                    statusSetByScan = true
                    manualGroup.visibility = View.VISIBLE
                }
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.root)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }

        // Remplacer le Bouncy Castle partiel d'Android par la version complète.
        Security.removeProvider("BC")
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())

        scanMrz = findViewById(R.id.scanMrz)
        manualToggle = findViewById(R.id.manualToggle)
        manualGroup = findViewById(R.id.manualGroup)
        docInput = findViewById(R.id.docInput)
        dobInput = findViewById(R.id.dobInput)
        expInput = findViewById(R.id.expInput)
        manualCan = findViewById(R.id.manualCan)
        detectedCard = findViewById(R.id.detectedCard)
        detectedType = findViewById(R.id.detectedType)
        detectedFields = findViewById(R.id.detectedFields)
        chipMrzValid = findViewById(R.id.chipMrzValid)
        canGroup = findViewById(R.id.canGroup)
        canInput = findViewById(R.id.canInput)
        status = findViewById(R.id.status)
        statusIcon = findViewById(R.id.statusIcon)
        progress = findViewById(R.id.progress)
        resultCard = findViewById(R.id.resultCard)
        photo = findViewById(R.id.photo)
        nameView = findViewById(R.id.name)
        fields = findViewById(R.id.fields)
        extra = findViewById(R.id.extra)
        chipIntegrity = findViewById(R.id.chipIntegrity)
        chipConsistency = findViewById(R.id.chipConsistency)
        chipClone = findViewById(R.id.chipClone)
        chipSignature = findViewById(R.id.chipSignature)

        val hasCamera = packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        scanMrz.visibility = if (hasCamera) View.VISIBLE else View.GONE
        scanMrz.setOnClickListener { launchScan(ScanActivity.MODE_MRZ) }
        findViewById<MaterialButton>(R.id.scanCan).apply {
            visibility = if (hasCamera) View.VISIBLE else View.GONE
            setOnClickListener { launchScan(ScanActivity.MODE_CAN) }
        }
        // Sans caméra, la saisie manuelle est le chemin nominal -> dépliée d'office.
        if (!hasCamera) manualGroup.visibility = View.VISIBLE

        manualToggle.setOnClickListener {
            manualGroup.visibility = if (manualGroup.isVisible) View.GONE else View.VISIBLE
        }
        findViewById<MaterialButton>(R.id.rescan).setOnClickListener { resetToScan() }

        findViewById<MaterialButton>(R.id.help).setOnClickListener {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.help).setMessage(R.string.help_text)
                .setPositiveButton(android.R.string.ok, null).show()
        }
        findViewById<View>(R.id.privacyRow).setOnClickListener {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.privacy_title).setMessage(R.string.privacy_text)
                .setPositiveButton(android.R.string.ok, null).show()
        }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        showIdle()
    }

    private fun launchScan(mode: String) {
        scanLauncher.launch(
            Intent(this, ScanActivity::class.java).putExtra(ScanActivity.EXTRA_MODE, mode)
        )
    }

    /** MRZ détectée : afficher le document reconnu et l'étape suivante (puce). */
    private fun onMrzScanned(mrz: MrzOcr.MrzData) {
        scanned = mrz
        resultCard.visibility = View.GONE
        val isId = mrz.docType == MrzOcr.DocType.ID_CARD
        val typeLabel = when (mrz.docType) {
            MrzOcr.DocType.PASSPORT -> R.string.doc_passport
            MrzOcr.DocType.ID_CARD -> R.string.doc_id_card
            MrzOcr.DocType.RESIDENCE_PERMIT -> R.string.doc_residence
        }
        detectedType.text = getString(
            R.string.detected_summary,
            getString(typeLabel),
            mrz.issuingState.ifBlank { "?" },
        )
        detectedFields.text = buildString {
            appendLine("Doc : ${mrz.documentNumber}")
            append("Naissance : ${mrz.dateOfBirth}   Expiration : ${mrz.dateOfExpiry}")
        }
        setChip(chipMrzValid, true, R.string.mrz_valid, R.string.mrz_valid, false)
        canGroup.visibility = if (isId) View.VISIBLE else View.GONE
        detectedCard.visibility = View.VISIBLE
        showTapStatus()
        statusSetByScan = true
    }

    private fun resetToScan() {
        scanned = null
        detectedCard.visibility = View.GONE
        resultCard.visibility = View.GONE
        canInput.text = null
        showIdle()
        statusSetByScan = true
    }

    override fun onResume() {
        super.onResume()
        val adapter = nfcAdapter
        when {
            adapter == null -> warn(getString(R.string.no_nfc))
            !adapter.isEnabled -> {
                warn(getString(R.string.nfc_disabled))
                status.setOnClickListener { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) }
            }
            else -> {
                status.setOnClickListener(null)
                status.isClickable = false
                if (!resultCard.isVisible && !statusSetByScan) {
                    if (scanned != null) showTapStatus() else showIdle()
                }
                statusSetByScan = false
                val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                val pending = PendingIntent.getActivity(this, 0, intent, flags)
                val filters = arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED))
                val techLists = arrayOf(arrayOf(IsoDep::class.java.name))
                adapter.enableForegroundDispatch(this, pending, filters, techLists)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (readJob?.isActive == true) return

        val tag: Tag = IntentCompat.getParcelableExtra(intent, NfcAdapter.EXTRA_TAG, Tag::class.java) ?: return
        val isoDep = IsoDep.get(tag) ?: run { warn(getString(R.string.not_isodep)); return }

        val req = buildRequest() ?: return

        showReading()
        resultCard.visibility = View.GONE
        readJob = lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching { CnieReader().read(isoDep, req.key, req.expectedMrz) }
            withContext(Dispatchers.Main) {
                result
                    .onSuccess { showResult(it) }
                    .onFailure { warn(getString(R.string.read_error, it.message ?: "?")) }
            }
        }
    }

    private data class AccessRequest(val key: AccessKey, val expectedMrz: MrzOcr.MrzData?)

    /** Construit la requête d'accès à partir de l'état (scan ou saisie manuelle). */
    private fun buildRequest(): AccessRequest? {
        val mrz = scanned
        if (mrz != null) {
            return if (mrz.docType == MrzOcr.DocType.ID_CARD) {
                // CNIe : PACE-CAN. Le CAN (recto) n'est pas dans la MRZ -> requis.
                val can = canInput.text?.toString()?.trim().orEmpty()
                if (can.length != 6 || !can.all { it.isDigit() }) {
                    warn(getString(R.string.enter_can)); null
                } else {
                    AccessRequest(AccessKey.Can(can), mrz)
                }
            } else {
                AccessRequest(AccessKey.Mrz(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry), mrz)
            }
        }

        // Saisie manuelle (aucun scan) : CAN -> CNIe ; sinon doc/naissance/expiration -> MRZ.
        val can = manualCan.text?.toString()?.trim().orEmpty()
        if (can.length == 6 && can.all { it.isDigit() }) {
            return AccessRequest(AccessKey.Can(can), null)
        }
        val doc = docInput.text?.toString()?.trim()?.uppercase().orEmpty()
        val dob = dobInput.text?.toString()?.trim().orEmpty()
        val exp = expInput.text?.toString()?.trim().orEmpty()
        val datesOk = dob.length == 6 && dob.all { it.isDigit() } && exp.length == 6 && exp.all { it.isDigit() }
        if (doc.isNotEmpty() && datesOk) {
            val manualMrz = MrzOcr.MrzData(doc, dob, exp, MrzOcr.DocType.PASSPORT, "")
            return AccessRequest(AccessKey.Mrz(doc, dob, exp), manualMrz)
        }
        warn(getString(R.string.scan_first))
        return null
    }

    private fun showResult(r: ReadResult) {
        nameView.text = "${r.surname} ${r.givenNames}".trim()
        fields.text = buildString {
            appendLine("Doc : ${r.documentNumber}    Nat : ${r.nationality}")
            append("Naissance : ${r.dateOfBirth}")
            r.dg13?.heightCm?.let { append("\nTaille : $it cm") }
        }
        val extraText = buildString {
            r.dg13?.address?.let { a ->
                val ligne = listOfNotNull(a.street, a.postalCode, a.city, a.country).joinToString(", ")
                if (ligne.isNotEmpty()) appendLine("Adresse : $ligne")
            }
            r.dg13?.birthPlace?.let { b ->
                val lieu = listOfNotNull(b.city, b.department).joinToString(", ")
                if (lieu.isNotEmpty()) append("Lieu de naissance : $lieu")
            }
        }.trim()
        extra.text = extraText
        extra.visibility = if (extraText.isEmpty()) View.GONE else View.VISIBLE

        setChip(chipIntegrity, r.hashesMatchSod, R.string.chip_integrity_ok, R.string.chip_integrity_bad, false)

        // Cohérence MRZ optique <-> puce : chip masqué si aucune MRZ n'a servi de référence.
        when (r.mrzMatchesScan) {
            null -> chipConsistency.visibility = View.GONE
            else -> {
                chipConsistency.visibility = View.VISIBLE
                setChip(chipConsistency, r.mrzMatchesScan, R.string.chip_consistency_ok, R.string.chip_consistency_bad, false)
            }
        }

        // Détection de clone.
        when (r.cloneCheck) {
            CloneCheck.AUTHENTIC -> setChip(chipClone, true, R.string.chip_clone_ok, R.string.chip_clone_ok, false)
            CloneCheck.FAILED -> setChip(chipClone, false, R.string.chip_clone_bad, R.string.chip_clone_bad, false)
            CloneCheck.UNSUPPORTED -> setChip(chipClone, false, R.string.chip_clone_na, R.string.chip_clone_na, true)
        }

        setChip(chipSignature, r.sodSignatureVerified, R.string.chip_sig_ok, R.string.chip_sig_unverified, true)

        photo.visibility = if (r.photo != null) View.VISIBLE else View.GONE
        r.photo?.let { photo.setImageBitmap(it) }

        resultCard.visibility = View.VISIBLE

        // Verdict global à 3 états — honnête pour de l'anti-fraude :
        //  - ROUGE : échec dur (intégrité KO, incohérence MRZ, ou clone détecté) ;
        //  - VERT : uniquement si la signature du SOD est chaînée à une CSCA de confiance
        //           (origine étatique prouvée) — pas encore implémenté ;
        //  - NEUTRE : lu et cohérent en interne, mais origine NON vérifiée (la seule
        //           cohérence des hashs auto-signés ne prouve pas l'authenticité).
        val hardFail = !r.hashesMatchSod || r.mrzMatchesScan == false || r.cloneCheck == CloneCheck.FAILED
        when {
            hardFail -> setStatus(getString(R.string.result_fail), R.drawable.ic_state_error, R.color.on_bad_container)
            r.sodSignatureVerified -> setStatus(getString(R.string.done), R.drawable.ic_state_ok, R.color.on_ok_container)
            else -> setStatus(getString(R.string.result_unverified), R.drawable.ic_state_info, R.color.on_neutral_container)
        }
    }

    // --- Statut ---

    private fun showIdle() = setStatus(getString(R.string.scan_prompt), R.drawable.ic_state_info, R.color.on_neutral_container)

    private fun showTapStatus() = setStatus(
        getString(if (scanned?.docType == MrzOcr.DocType.ID_CARD) R.string.tap_id else R.string.tap_mrz),
        R.drawable.ic_state_info,
        R.color.on_neutral_container,
    )

    private fun warn(text: String) = setStatus(text, R.drawable.ic_state_error, R.color.on_bad_container)

    private fun showReading() {
        progress.visibility = View.VISIBLE
        statusIcon.visibility = View.GONE
        status.text = getString(R.string.reading)
    }

    private fun setStatus(text: String, @DrawableRes icon: Int, @ColorRes tint: Int) {
        progress.visibility = View.GONE
        statusIcon.visibility = View.VISIBLE
        statusIcon.setImageResource(icon)
        statusIcon.setColorFilter(ContextCompat.getColor(this, tint))
        status.text = text
    }

    /** Colore un chip : vert (OK), rouge (échec) ou neutre (indéterminé). */
    private fun setChip(chip: Chip, ok: Boolean, @StringRes okText: Int, @StringRes koText: Int, neutralIfNotOk: Boolean) {
        val (bg, fg, text) = when {
            ok -> Triple(R.color.ok_container, R.color.on_ok_container, okText)
            neutralIfNotOk -> Triple(R.color.neutral_container, R.color.on_neutral_container, koText)
            else -> Triple(R.color.bad_container, R.color.on_bad_container, koText)
        }
        chip.text = getString(text)
        chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(this, bg))
        chip.setTextColor(ContextCompat.getColor(this, fg))
    }
}
