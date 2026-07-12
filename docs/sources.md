# Sources & données

Veripuce ne télécharge rien à l'usage : il embarque tout ce dont il a besoin pour prouver
l'origine étatique d'un document. Ce document détaille la provenance de ces données et les jeux
de test cryptographiques.

- [1. Le magasin de confiance CSCA](#1-le-magasin-de-confiance-csca)
- [2. Format auditable](#2-format-auditable)
- [3. Recoupement et garde-fous](#3-recoupement-et-garde-fous)
- [4. Rafraîchissement automatique](#4-rafraîchissement-automatique)
- [5. Jeux de test cryptographiques](#5-jeux-de-test-cryptographiques)

---

## 1. Le magasin de confiance CSCA

Pour prouver qu'un document est « émis par l'État », il faut vérifier que son certificat
signataire (DSC) remonte à une **CSCA** (*Country Signing Certification Authority*) de confiance.
Veripuce embarque **773 certificats CSCA** dans `app/src/main/assets/csca/`, union dédupliquée de
**trois sources officielles indépendantes** :

| Source | Édition embarquée | Contribution |
|---|---|---|
| **Masterlist ICAO** (aviation civile internationale) | `ICAO_ML_20260708111336.ml` | 572 certs |
| **Masterlist BSI** (office fédéral allemand de la sécurité) | `DE_ML_2026-05-28-08-28-45.ml` | 588 certs |
| **ANTS** (France) | CSCA-FRANCE 2010/2015/2020/2025 + **eID-FRANCE** | 5 certs |

*(Les éditions exactes et URLs sont en tête de [`assets/csca/MANIFEST.tsv`](../app/src/main/assets/csca/MANIFEST.tsv).)*

Recouvrement dans l'union : 385 certs communs ICAO+BSI, 3 CSCA-FRANCE présentes dans les trois
canaux, et **eID-FRANCE** fournie par l'ANTS seule (c'est la CSCA e-ID de la CNIe, absente des
masterlists « voyage » — sans elle, aucune CNIe ne pourrait être prouvée « émise par l'État »).

---

## 2. Format auditable

**Un fichier PEM par certificat**, pour qu'un audit puisse justifier chaque ancre de confiance
individuellement. Nommage : `<pays>_<CN>_<sources>_<sha256>.pem`, par ex.

```
FR_CSCA-FRANCE_icao-bsi-ants_d628b510.pem   ← présent dans ICAO, BSI ET publié par l'ANTS
FR_eID-FRANCE_ants_b33ea63b.pem             ← publié par l'ANTS seule (normal pour l'e-ID)
```

Chaque fichier porte en **en-tête** (commentaires, ignorés au chargement) : sujet, émetteur,
numéro de série, validité, empreinte SHA-256 complète, et **la ou les sources exactes**. Le
fichier [`MANIFEST.tsv`](../app/src/main/assets/csca/MANIFEST.tsv) récapitule le magasin (une
ligne par certificat) : chaque mise à jour devient ainsi un **diff git lisible**, certificat par
certificat, plutôt qu'un blob binaire opaque.

La sortie est **déterministe et sans date** : mêmes sources → fichiers octet-pour-octet
identiques → pas de faux diff. La date d'entrée/sortie d'un certificat se lit dans l'historique
git de son fichier.

---

## 3. Recoupement et garde-fous

Le générateur [`tools/csca/update_csca.py`](../tools/csca/update_csca.py) applique plusieurs
contrôles à chaque exécution :

1. **Signature CMS de chaque masterlist vérifiée** à l'extraction (`openssl cms -verify -binary`).
   Sans l'option `-binary`, openssl corromprait l'eContent DER — piège appris à la dure.
2. **Recoupement octet-pour-octet des CSCA françaises** entre canaux indépendants : chaque CSCA
   ANTS est recherchée par empreinte SHA-256 dans les masterlists ICAO et BSI. Une CSCA-FRANCE
   passeport ≥ 2015 absente des deux masterlists ⇒ **dépôt refusé** (canal ANTS suspect).
   eID-FRANCE est exemptée (absente des masterlists « voyage », attendu).
3. **Plancher France** : au moins 5 certificats FR requis, sinon échec (le magasin en a 9).
4. **Validation stricte** : seuls les certificats parsables sont gardés. Un repli `openssl`
   récupère les CSCA à encodage laxiste (numéros de série DER négatifs — Japon —, paramètres NULL
   sur ECDSA) que la bibliothèque `cryptography ≥ 43` rejette, avec une sortie alignée bit à bit.
5. **Certificats de TEST de l'ANTS jamais inclus** (filtre sur « test » dans le nom).

Le test [`CscaBundleTest`](../app/src/test/java/fr/veripuce/app/CscaBundleTest.kt) vérifie en
continu l'intégrité du magasin : ≥ 700 certs chargés, présence des CSCA françaises (passeport +
eID), 1 fichier = 1 certificat, empreinte du nom conforme au contenu, et MANIFEST cohérent.

---

## 4. Rafraîchissement automatique

Les masterlists sont rééditées tous les 1 à 3 mois. Le workflow
[`update-csca.yml`](../.github/workflows/update-csca.yml) tourne **chaque lundi** (+ déclenchement
manuel) :

- dépendances **épinglées** (`cryptography==49.0.0`, `requests==2.34.2`) pour la reproductibilité ;
- régénère le magasin, puis applique deux gardes : **« mêmes éditions ⇒ magasin identique »**
  (un diff à sources inchangées = dérive d'environnement → échec bruyant) et
  **anti-rétrécissement** (> 10 % de certs perdus = revue manuelle) ;
- lance les tests unitaires, puis **ouvre une PR** (jamais de fusion automatique) : l'ancre de
  confiance de toute la vérification reste **relue par un humain**.

En local : `python tools/csca/update_csca.py`.

---

## 5. Jeux de test cryptographiques

La *passive authentication* est testée sur deux fronts : des données que **nous générons** (pour
maîtriser la matrice d'algorithmes et les cas négatifs) et des données produites par des **tiers
officiels** (pour l'interopérabilité).

### PKI de test générée à la volée

- [`PassiveAuthTest`](../app/src/test/java/fr/veripuce/app/PassiveAuthTest.kt) — une CSCA de test
  → un DSC → un SOD signé par JMRTD, comme le ferait un État. Couvre intégrité (OK / DG altéré /
  aucun DG) et les 4 verdicts de signature (`TRUSTED`, `VALID_UNTRUSTED`, `INVALID`,
  indépendance signature/intégrité).
- [`AlgorithmMatrixTest`](../app/src/test/java/fr/veripuce/app/AlgorithmMatrixTest.kt) — matrice
  d'algorithmes :

  | Empreinte | Signature | Clé / courbe |
  |---|---|---|
  | SHA-1 / 256 / 512 | RSA PKCS#1 v1.5 | RSA 2048 |
  | SHA-256 | ECDSA | secp256r1 (NIST P-256) |
  | SHA-256 | ECDSA | **brainpoolP256r1** |
  | SHA-384 | ECDSA | **brainpoolP384r1** |

  Les courbes *brainpool* sont celles des CSCA/DSC français et allemands — inconnues du provider
  par défaut d'Android comme de la JVM : ce test exerce **pour de vrai** le repli BouncyCastle de
  la vérification de chaîne.

### Fixtures externes officielles

| Jeu | Origine | Algorithme | Rôle |
|---|---|---|---|
| **BSI TR-03105-5** | Office fédéral allemand (jeu de référence officiel) | RSASSA-PSS / SHA-256 | golden set positif ; couvre PSS |
| **bsi2008** | Jeu de référence BSI 2008 (fixtures JMRTD) | ECDSA / SHA-1 | algorithmes anciens |
| **loes2006** | Passeport de test néerlandais « Loes » | RSA v1.5 / SHA-256 | interopérabilité RSA v1.5 |

Chaque jeu est vérifié indépendamment (empreintes recalculées avant dépôt) et documenté dans son
`README.txt`. Certains contiennent un DG volontairement discordant, utilisé comme **cas négatif
réel**. Tous sont signés par des **certificats de test** — jamais dans le magasin de production
(un test dédié vérifie que le magasin réel ne reconnaît aucun DSC de test).

Bilan de couverture : RSA PKCS#1 v1.5 (SHA-1/256/512), RSASSA-PSS, ECDSA (SHA-1 externe,
SHA-256/384 générés, courbes NIST **et** brainpool).
