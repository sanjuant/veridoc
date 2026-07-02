package fr.example.cnie

import android.graphics.Bitmap
import android.nfc.tech.IsoDep
import com.gemalto.jp2.JP2Decoder
import net.sf.scuba.smartcards.CardService
import org.jmrtd.PACEKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import java.security.MessageDigest

/**
 * Lecture d'une CNIe française via NFC.
 *
 * Flux : IsoDep -> CardService (SCUBA) -> PassportService (JMRTD) -> PACE-CAN
 * -> lecture des data groups -> passive authentication (intégrité).
 *
 * NB : squelette d'architecture. Certaines signatures JMRTD/SCUBA varient selon la
 * version épinglée (voir README) — à réconcilier, l'ordre des appels étant stable.
 */
class CnieReader {

    fun read(isoDep: IsoDep, can: String): ReadResult {
        require(can.length == 6 && can.all { it.isDigit() }) { "Le CAN doit faire 6 chiffres." }

        isoDep.timeout = 15_000

        // 1) Transport : envelopper l'IsoDep Android dans un CardService SCUBA.
        //    (Selon la version de scuba-sc-android, l'entrée peut différer —
        //     CardService.getInstance(isoDep) est le point d'entrée usuel.)
        val cardService = CardService.getInstance(isoDep)
        cardService.open()

        val service = PassportService(
            cardService,
            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            /* isSFIEnabled = */ false,
            /* shouldCheckMAC = */ false,
        )
        service.open()

        // 2) PACE avec le CAN.
        //    On lit d'abord EF.CardAccess pour récupérer l'OID PACE et les paramètres
        //    de domaine (BrainpoolP256r1 sur la CNI).
        val cardAccess = CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS))
        val paceInfo = cardAccess.securityInfos.filterIsInstance<PACEInfo>().first()

        val canKey = PACEKeySpec.createCANKey(can)
        service.doPACE(
            canKey,
            paceInfo.objectIdentifier,
            PACEInfo.toParameterSpec(paceInfo.parameterId),
            null,
        )

        // Après PACE, (re)sélectionner l'application eMRTD en mode authentifié.
        service.sendSelectApplet(true)

        // 3) Lecture des data groups. DG1 = MRZ, DG2 = image faciale.
        //    (DG11/DG12 = état civil détaillé si besoin.)
        val dg1 = DG1File(service.getInputStream(PassportService.EF_DG1))
        val dg2 = DG2File(service.getInputStream(PassportService.EF_DG2))

        val mrz = dg1.mrzInfo

        // Photo : bytes -> JPEG 2000 (ou JPEG). Décodage via le décodeur Gemalto,
        // Android n'ayant pas javax.imageio.
        val faceImageInfo = dg2.faceInfos.first().faceImageInfos.first()
        val imageBytes = faceImageInfo.imageInputStream.readBytes()
        val photo: Bitmap? = runCatching { JP2Decoder(imageBytes).decode() }.getOrNull()

        // DG13 : spécifique France (adresse, taille, lieu de naissance). Optionnel :
        // on lit les octets bruts (JMRTD ne parse pas ce DG propriétaire) puis on
        // applique Dg13Parser. On garde les octets pour la vérif d'intégrité.
        // NB : si EF_DG13 n'existe pas comme constante dans ta version, utilise 0x010D.
        val dg13Bytes: ByteArray? = runCatching {
            service.getInputStream(PassportService.EF_DG13).readBytes()
        }.getOrNull()
        val dg13: Dg13? = dg13Bytes?.let { runCatching { Dg13Parser.parse(it) }.getOrNull() }

        // 4) Passive authentication — le cœur anti-fraude.
        //    (a) intégrité : les hashs recalculés des DG doivent correspondre à ceux,
        //        signés, stockés dans le SOD (DG13 inclus s'il a été lu).
        val sod = SODFile(service.getInputStream(PassportService.EF_SOD))
        val integrityOk = verifyDataGroupHashes(
            sod,
            buildMap {
                put(1, dg1.encoded)
                put(2, dg2.encoded)
                dg13Bytes?.let { put(13, it) }
            },
        )

        // (b) authenticité : vérifier la signature du SOD puis chaîner le DSC jusqu'à
        //     une CSCA de confiance (France : ANTS). Nécessite un trust store CSCA.
        // TODO: sod.docSigningCertificate -> vérifier signature du SOD
        // TODO: valider la chaîne DSC -> CSCA depuis un KeyStore de CSCA de confiance
        val signatureVerified = false // tant que le trust store CSCA n'est pas branché

        return ReadResult(
            mrz = mrz.toString(),
            documentNumber = mrz.documentNumber,
            surname = mrz.primaryIdentifier,
            givenNames = mrz.secondaryIdentifier,
            dateOfBirth = mrz.dateOfBirth,
            nationality = mrz.nationality,
            photo = photo,
            dg13 = dg13,
            hashesMatchSod = integrityOk,
            sodSignatureVerified = signatureVerified,
        )
    }

    /** Recalcule le hash de chaque DG et le compare au hash signé du SOD. */
    private fun verifyDataGroupHashes(sod: SODFile, dgEncoded: Map<Int, ByteArray>): Boolean {
        val md = MessageDigest.getInstance(sod.digestAlgorithm) // ex. "SHA-256"
        val stored = sod.dataGroupHashes
        return dgEncoded.all { (num, bytes) ->
            stored[num]?.contentEquals(md.digest(bytes)) == true
        }
    }
}
