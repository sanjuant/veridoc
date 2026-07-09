"""Régénère app/src/main/assets/csca/csca-trusted.pem depuis les sources officielles.

Usage :  python tools/csca/update_csca.py            (depuis la racine du dépôt)
Prérequis : python 3.10+, `pip install cryptography requests`, openssl dans le PATH.

Sources (URLs pérennes, re-résolues à chaque exécution) :
  - Masterlist ICAO : le nom du fichier courant est scrapé depuis la page de
    consentement publique d'icao.int (il change à chaque édition, ~trimestrielle).
  - Masterlist BSI (Allemagne) : URL sans paramètre de version -> toujours la dernière
    édition (zip contenant un .ml CMS). GET uniquement (le WAF du BSI bloque HEAD).
  - ANTS (France) : les 4 générations CSCA-FRANCE + eID-FRANCE (CNIe). Les URLs UUID
    d'img.ants.gouv.fr peuvent changer si l'ANTS re-téléverse — si un lien 404,
    re-scraper https://ants.gouv.fr/csca et /eid dans un navigateur (pages JS-only).

Garde-fous :
  - `openssl cms -verify -binary` vérifie la signature CMS de chaque masterlist
    (l'option -binary est CRITIQUE : sans elle openssl corrompt l'eContent DER).
  - Contrôle croisé : les CSCA françaises de l'ANTS doivent être identiques
    octet-pour-octet à celles des masterlists ICAO/BSI (canaux indépendants).
  - Seuls les certificats parsables strictement sont gardés (un cert malformé
    ferait rejeter tout le bundle par CertificateFactory sur Android).
  - Les certificats de TEST de l'ANTS ne sont jamais inclus.
"""
import base64
import collections
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "app/src/main/assets/csca/csca-trusted.pem"

ICAO_DISCOVERY = "https://www.icao.int/sites/default/files/Security/FAL/Consent_Google_ReCaptcha_new.html"
ICAO_BASE = "https://www.icao.int/sites/default/files/Security/FAL/"
BSI_ZIP = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile"
ANTS = {  # nom -> zip img.ants.gouv.fr (miroir direct, sans la protection anti-bot du site)
    "CSCA-FRANCE_2025": "https://img.ants.gouv.fr/78710fab-d613-43a6-9123-e740181f5550.zip",
    "CSCA-FRANCE_2020": "https://img.ants.gouv.fr/9fcbd13c-19a7-406d-ae0f-d4ff68ee247f.zip",
    "CSCA-FRANCE_2015": "https://img.ants.gouv.fr/6c2a08a3-719b-45c9-95b4-bc68b993a89f.zip",
    "CSCA-FRANCE_2010": "https://img.ants.gouv.fr/dc3345f5-3e91-44e7-9f62-47bcfd0e24fc.zip",
    "eID-FRANCE": "https://img.ants.gouv.fr/ba66b9a1-bb09-4c0b-ad27-ce39d038a6e6.zip",
}
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def fetch(url, what):
    r = requests.get(url, headers=UA, timeout=120)
    r.raise_for_status()
    if b"<html" in r.content[:500].lower():
        sys.exit(f"ERREUR: {what} a renvoyé une page HTML (protection anti-bot ?) : {url}")
    print(f"  {what}: {len(r.content)} octets")
    return r.content


# ---------- DER / CMS ----------

def der_len(buf, off):
    first = buf[off]
    if first < 0x80:
        return 1, first
    n = first & 0x7F
    return 1 + n, int.from_bytes(buf[off + 1:off + 1 + n], "big")


def iter_tlv(buf, start, end):
    off = start
    while off < end:
        tlv_start = off
        tag = buf[off]
        off += 1
        if tag & 0x1F == 0x1F:
            while buf[off] & 0x80:
                off += 1
            off += 1
        lhdr, clen = der_len(buf, off)
        off += lhdr
        yield tag, tlv_start, off, off + clen
        off += clen


def certs_from_masterlist(ml_der):
    """CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }"""
    out = []
    for tag, _s, c_s, c_e in iter_tlv(ml_der, 0, len(ml_der)):
        if tag != 0x30:
            continue
        for t2, _s2, cs2, ce2 in iter_tlv(ml_der, c_s, c_e):
            if t2 == 0x31:
                for t3, s3, _cs3, ce3 in iter_tlv(ml_der, cs2, ce2):
                    if t3 == 0x30:
                        out.append(bytes(ml_der[s3:ce3]))
        break
    return out


def cms_masterlist_certs(cms_bytes, name):
    """Extrait les certificats d'une masterlist CMS ; la signature CMS est vérifiée
    (contre le signataire embarqué ; -noverify ne saute que le chaînage du signataire)."""
    with tempfile.TemporaryDirectory() as td:
        inp, outp = Path(td) / "in.cms", Path(td) / "out.der"
        inp.write_bytes(cms_bytes)
        r = subprocess.run(
            ["openssl", "cms", "-verify", "-noverify", "-binary",
             "-inform", "DER", "-in", str(inp), "-out", str(outp)],
            capture_output=True,
        )
        if r.returncode != 0:
            sys.exit(f"ERREUR: signature CMS invalide pour {name}: {r.stderr.decode(errors='replace')[:300]}")
        certs = certs_from_masterlist(outp.read_bytes())
    print(f"  {name}: {len(certs)} certificats (signature CMS OK)")
    return certs


def zip_members(data, suffix):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist() if n.lower().endswith(suffix)}


def main():
    print("== 1/4 Téléchargements ==")
    consent = requests.get(ICAO_DISCOVERY, headers=UA, timeout=60).text
    m = re.search(r"MasterList/ICAO_ML_\d+\.ml", consent)
    if not m:
        sys.exit("ERREUR: nom de la masterlist ICAO introuvable sur la page de consentement")
    icao_ml = fetch(ICAO_BASE + m.group(0), f"ICAO {m.group(0)}")

    bsi_zip = fetch(BSI_ZIP, "BSI GermanMasterList.zip")
    mls = zip_members(bsi_zip, ".ml")
    if len(mls) != 1:
        sys.exit(f"ERREUR: {len(mls)} fichiers .ml dans le zip BSI (1 attendu): {list(mls)}")
    (bsi_name, bsi_ml), = mls.items()

    ants_ders = {}
    for name, url in ANTS.items():
        crts = zip_members(fetch(url, f"ANTS {name}"), ".crt")
        crts = {n: b for n, b in crts.items() if "test" not in n.lower()}
        if len(crts) != 1:
            sys.exit(f"ERREUR: {len(crts)} .crt dans le zip ANTS {name} (1 attendu): {list(crts)}")
        ants_ders[name] = next(iter(crts.values()))

    print("== 2/4 Extraction des masterlists ==")
    icao_certs = cms_masterlist_certs(icao_ml, "ICAO")
    bsi_certs = cms_masterlist_certs(bsi_ml, f"BSI {bsi_name}")
    icao_h = {hashlib.sha256(c).hexdigest() for c in icao_certs}
    bsi_h = {hashlib.sha256(c).hexdigest() for c in bsi_certs}

    print("== 3/4 Contrôle croisé des CSCA françaises (canaux indépendants) ==")
    for name, der in ants_ders.items():
        h = hashlib.sha256(der).hexdigest()
        where = [s for s, hs in (("ICAO", icao_h), ("BSI", bsi_h)) if h in hs]
        print(f"  {name}: présent dans {where or 'ANTS uniquement'}")
        # eID-FRANCE (CSCA e-ID) n'est pas un cert « document de voyage » : absent des
        # masterlists, c'est attendu. Les CSCA passeport récentes doivent recouper.
        if name.startswith("CSCA-FRANCE") and name >= "CSCA-FRANCE_2015" and not where:
            sys.exit(f"ERREUR: {name} absent des masterlists ICAO et BSI — canal ANTS suspect, dépôt refusé")

    print("== 4/4 Dédup, validation stricte, écriture ==")
    seen, kept, bad = set(), [], 0
    countries = collections.Counter()
    for der in icao_certs + bsi_certs + list(ants_ders.values()):
        h = hashlib.sha256(der).digest()
        if h in seen:
            continue
        seen.add(h)
        try:
            cert = x509.load_der_x509_certificate(der)
            c = next((a.value for a in cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)), "??")
        except Exception:
            bad += 1
            continue
        countries[c] += 1
        kept.append(cert)

    if countries["FR"] < 5:
        sys.exit(f"ERREUR: seulement {countries['FR']} certs FR (>=5 attendus) — dépôt refusé")

    with open(OUT, "wb") as f:
        for cert in kept:
            f.write(cert.public_bytes(Encoding.PEM))
    print(f"\n{OUT}")
    print(f"{len(kept)} certificats uniques ({bad} illisibles écartés), FR={countries['FR']}, "
          f"{OUT.stat().st_size} octets")
    print("Pensez à mettre à jour la date et les éditions dans assets/csca/README.txt,")
    print("puis lancez les tests : ./gradlew testDebugUnitTest")


if __name__ == "__main__":
    main()
