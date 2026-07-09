Magasin de certificats CSCA de confiance (ancre de confiance de la passive authentication).

FORMAT AUDITABLE : un fichier PEM par certificat, nommé

    <pays>_<CN>_<sources>_<sha256 tronqué>.pem
    ex. FR_CSCA-FRANCE_icao-bsi-ants_d628b510.pem
        -> présent dans la masterlist ICAO, la masterlist BSI ET publié par l'ANTS.

Chaque fichier porte en tête (commentaires ignorés au parsing) : sujet, émetteur, numéro
de série, validité, empreinte SHA-256 complète et source(s) exacte(s) avec édition/URL.
MANIFEST.tsv récapitule le magasin (éditions des sources en tête, une ligne par certificat).
La date d'entrée/sortie d'un certificat se lit dans l'historique git de son fichier —
chaque mise à jour est un diff lisible certificat par certificat.

Sources officielles indépendantes (union dédupliquée, éditions exactes dans MANIFEST.tsv) :

  1. Masterlist ICAO      https://www.icao.int/icao-pkd/icao-master-list
  2. Masterlist BSI (DE)  https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html
  3. ANTS (France)        https://ants.gouv.fr/csca et https://ants.gouv.fr/eid :
     CSCA-FRANCE 2010/2015/2020/2025 (passeports, CNIe, titres de séjour)
     + eID-FRANCE (CSCA e-ID de la CNIe, absente des masterlists « voyage »)

Contrôles effectués à CHAQUE génération (tools/csca/update_csca.py) :
  - signature CMS de chaque masterlist vérifiée à l'extraction ;
  - CSCA françaises recoupées octet-pour-octet entre canaux indépendants
    (génération refusée si les CSCA passeport récentes ne recoupent pas, ou si < 5 certs FR) ;
  - seuls les certificats strictement parsables sont gardés.
Référence pour eID-FRANCE (publiée par l'ANTS, certificat valable jusqu'en 2036) :
  SHA-256  B3:3E:A6:3B:9B:E0:10:82:D9:80:71:A2:91:11:75:7C:72:25:7E:BA:80:D7:20:5D:21:FA:35:43:6C:29:FE:7C

Mise à jour : python tools/csca/update_csca.py, ou automatiquement via l'action planifiée
.github/workflows/update-csca.yml (hebdomadaire, ouvre une PR à relire — jamais de fusion
automatique). Le test CscaBundleTest vérifie l'intégrité du magasin : 1 fichier = 1
certificat, empreinte du nom conforme au contenu, manifest cohérent, CSCA françaises présentes.

Formats acceptés par l'application : DER (.cer/.der/.crt) et PEM (.pem, multi-certs).
Ces certificats sont PUBLICS (clés publiques d'autorités) — ce ne sont pas des secrets.
Ce README et MANIFEST.tsv sont ignorés au chargement (seules les extensions ci-dessus sont lues).

JAMAIS déposer ici les certificats de TEST publiés par l'ANTS (CSCA-FRANCE TEST,
CSCA-eID-FRANCE TEST) : ils rendraient « authentiques » des documents de test.
