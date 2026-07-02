package fr.example.cnie

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.Security

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null

    private lateinit var canInput: EditText
    private lateinit var status: TextView
    private lateinit var mrzView: TextView
    private lateinit var photoView: ImageView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Remplacer le Bouncy Castle partiel d'Android par la version complète.
        Security.removeProvider("BC")
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())

        canInput = findViewById(R.id.canInput)
        status = findViewById(R.id.status)
        mrzView = findViewById(R.id.mrz)
        photoView = findViewById(R.id.photo)
        findViewById<Button>(R.id.help).setOnClickListener {
            status.text = getString(R.string.hint_tap)
        }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) status.text = getString(R.string.no_nfc)
    }

    override fun onResume() {
        super.onResume()
        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        val pending = PendingIntent.getActivity(this, 0, intent, flags)
        val filters = arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED))
        val techLists = arrayOf(arrayOf(IsoDep::class.java.name))
        nfcAdapter?.enableForegroundDispatch(this, pending, filters, techLists)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val tag: Tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG) ?: return
        val isoDep = IsoDep.get(tag) ?: run {
            status.text = getString(R.string.not_isodep); return
        }

        val can = canInput.text.toString().trim()
        if (can.length != 6 || !can.all { it.isDigit() }) {
            status.text = getString(R.string.enter_can); return
        }

        status.text = getString(R.string.reading)
        lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching { CnieReader().read(isoDep, can) }
            withContext(Dispatchers.Main) {
                result
                    .onSuccess { showResult(it) }
                    .onFailure { status.text = getString(R.string.read_error, it.message ?: "?") }
            }
        }
    }

    private fun showResult(r: ReadResult) {
        mrzView.text = buildString {
            appendLine("${r.surname} ${r.givenNames}")
            appendLine("Doc : ${r.documentNumber}   Nat : ${r.nationality}")
            appendLine("Naissance : ${r.dateOfBirth}")

            r.dg13?.let { dg13 ->
                appendLine()
                dg13.heightCm?.let { appendLine("Taille : $it cm") }
                dg13.address?.let { a ->
                    val ligne = listOfNotNull(a.street, a.postalCode, a.city, a.country)
                        .joinToString(", ")
                    if (ligne.isNotEmpty()) appendLine("Adresse : $ligne")
                }
                dg13.birthPlace?.let { b ->
                    val lieu = listOfNotNull(b.city, b.department).joinToString(", ")
                    if (lieu.isNotEmpty()) appendLine("Lieu de naissance : $lieu")
                }
            }

            appendLine()
            appendLine("Intégrité (hashs = SOD) : ${if (r.hashesMatchSod) "OK" else "ÉCHEC"}")
            append("Signature SOD (CSCA)     : ${if (r.sodSignatureVerified) "OK" else "non vérifiée"}")
        }
        r.photo?.let { photoView.setImageBitmap(it) }
        status.text = getString(R.string.done)
    }
}
