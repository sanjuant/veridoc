# Calcul des clés d'accès

Pour lire une puce eMRTD, il faut d'abord ouvrir une **session sécurisée**. La puce n'y consent
que si l'application prouve qu'elle a un accès *physique* au document, via un secret imprimé
dessus. Ce document explique comment ce secret devient une clé, et comment Veripuce fiabilise
le processus.

- [1. Deux secrets possibles : MRZ ou CAN](#1-deux-secrets-possibles--mrz-ou-can)
- [2. Dérivation de la clé MRZ (ICAO 9303-11)](#2-dérivation-de-la-clé-mrz-icao-9303-11)
- [3. Le CAN, mot de passe alternatif](#3-le-can-mot-de-passe-alternatif)
- [4. PACE et BAC](#4-pace-et-bac)
- [5. Candidats de clé sur paires aveugles](#5-candidats-de-clé)
- [6. Stratégie complète d'ouverture](#6-stratégie-complète-douverture)

---

## 1. Deux secrets possibles : MRZ ou CAN

La norme ICAO 9303-11 définit deux **mots de passe** possibles pour PACE :

- **la MRZ** — dérivée du numéro de document + date de naissance + date d'expiration (la bande
  de caractères en bas du document). C'est le mot de passe **obligatoire** par la norme.
- **le CAN** (*Card Access Number*) — 6 chiffres imprimés au recto, mot de passe **optionnel**
  et *indépendant* (il ne se calcule pas depuis la MRZ).

Veripuce modélise ces deux voies par `AccessKey.Mrz(...)` et `AccessKey.Can(...)`
(`AccessKey.kt:16-24`). La voie **MRZ est le cas nominal pour tous les documents**, y compris
les cartes d'identité : la CNIe française (applet IDEMIA « PACE passwords: MRZ, CAN, PIN, PUK »)
et la CNIE marocaine 2020+ acceptent la clé MRZ. Le CAN n'intervient qu'en **repli**.

---

## 2. Dérivation de la clé MRZ (ICAO 9303-11)

La clé ne se calcule pas dans Veripuce : le code construit un `BACKey` et délègue à JMRTD
(`PACEKeySpec.createMRZKey(...)`). Voici néanmoins la dérivation standard que JMRTD applique, car
elle explique la **sensibilité aux erreurs OCR** (§5).

### Étape 1 — la « MRZ_information »

On concatène trois champs, **chacun suivi de son chiffre de contrôle** :

```
MRZ_information =  numéro_document(9) + cd_doc
                + date_naissance(AAMMJJ) + cd_naissance
                + date_expiration(AAMMJJ) + cd_expiration
```

> Le numéro est pris sur **9 caractères en position 6–14 de la ligne 1** (TD1) ou de la ligne 2
> (TD3) — pas le CAN, pas un autre numéro imprimé. Les dates sont au format AAMMJJ exact de la MRZ.

### Étape 2 — le condensat

```
Kseed = SHA-1(MRZ_information)      (20 octets)
```

### Étape 3 — l'usage

| Protocole | Mot de passe utilisé |
|---|---|
| **BAC** | les **16 premiers octets** de `Kseed` (clés 3DES) |
| **PACE** | le **condensat SHA-1 complet (20 octets)** comme mot de passe π |

**Effet avalanche** : SHA-1 diffuse chaque bit d'entrée sur toute la sortie. Un **seul caractère
faux** dans le numéro de document produit une clé totalement différente → la puce refuse
(SW `0x6300`). C'est pourquoi une confusion OCR indétectable par le chiffre de contrôle (une
« paire aveugle », voir [Algorithmes §4](algorithmes.md#4-paires-aveugles-et-robustesse-ocr))
suffit à faire échouer l'ouverture par clé MRZ.

### Dans le code

```kotlin
// clé MRZ (CnieReader.kt:265)
PACEKeySpec.createMRZKey(BACKey(docNumber, mrz.dateOfBirth, mrz.dateOfExpiry))

// repli BAC (CnieReader.kt:250,284)
service.doBAC(BACKey(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry))
```

`BACKey` encapsule les trois champs ; `createMRZKey` construit le mot de passe π selon 9303-11.

---

## 3. Le CAN, mot de passe alternatif

Les 6 chiffres du recto sont utilisés **directement** comme mot de passe PACE (pas de dérivation
SHA-1) :

```kotlin
// CnieReader.kt:218-220
require(can.length == 6 && can.all { it.isDigit() })
PACEKeySpec.createCANKey(can)
```

Le CAN étant un secret indépendant de la MRZ, une session ouverte par CAN permet en plus de
**vérifier** que la MRZ scannée correspond bien à la puce (contrôle de cohérence) — ce qu'une
ouverture par clé MRZ ne peut pas prouver (la clé dérive déjà de la MRZ).

---

## 4. PACE et BAC

- **PACE** (*Password Authenticated Connection Establishment*) — protocole moderne : un
  échange Diffie-Hellman est « brouillé » par le mot de passe. Résistant au brute-force hors
  ligne. C'est le protocole des documents récents (CNIe, passeports 2015+).
- **BAC** (*Basic Access Control*) — protocole ancien (passeports d'avant ~2015), basé sur
  3DES. Utilisé **en repli** quand la puce n'annonce aucun PACE. La CNIe française est
  *PACE-only* (jamais de BAC).

Veripuce essaie **tous** les protocoles PACE annoncés par la puce, ECDH-GM en premier
(`CnieReader.kt:356-363`) — détaillé dans [Algorithmes §5](algorithmes.md#5-ouverture-de-la-session-pace--bac).

---

## 5. Candidats de clé

Quand une carte d'identité refuse la clé MRZ (SW `0x6300`) alors que la MRZ passe pourtant tous
ses chiffres de contrôle, le suspect n°1 est une **paire aveugle** dans le numéro de document
(un `G` lu `6`, un `L` lu `1`…). Plutôt que de basculer aussitôt sur le CAN, Veripuce **regénère
des variantes du numéro** et retente PACE avec chacune.

`documentNumberCandidates(documentNumber, limit = 4)` (`MrzKeyCandidates.kt:38-48`) :
- l'original est essayé **en premier** ;
- puis, position par position, chaque substitution de paire aveugle produit une variante ;
- **bornage strict** : au plus **4 essais** (original + 3 variantes), `break` dès la limite
  atteinte. Chaque essai ≈ une session PACE ≈ 1 s.

Par construction, ces variantes **conservent le chiffre de contrôle ICAO** (c'est justement
pourquoi elles étaient indétectables) : inutile de les re-valider. Et c'est **la puce qui
tranche** — une variante fausse est refusée, la bonne ouvre la session. Aucune reconnaissance
optique parfaite n'est nécessaire : il suffit d'arriver à ~3 substitutions près.

> **Confidentialité** : le libellé de la tentative dans le rapport de diagnostic ne révèle que la
> **position** retentée (`MRZ-candidat(pos=X)`), jamais le caractère — car sur une réussite, ce
> caractère serait la valeur réelle de la puce (`CnieReader.kt:299-303`). Voir
> [Sécurité & confidentialité](securite-confidentialite.md#le-rapport-de-diagnostic-caviardé).

---

## 6. Stratégie complète d'ouverture

`openWithMrz` (`CnieReader.kt:235-292`) résume la logique :

```
1. Lire EF.CardAccess (protocoles PACE annoncés).
2. Aucun PACE annoncé ?  → BAC (document ancien ; jamais une CNIe française).
3. Carte d'identité ?    → générer les candidats (paires aveugles).
   Sinon (passeport, titre de séjour) → un seul candidat : le numéro tel quel.
4. Pour chaque candidat, tenter PACE (tous protocoles, GM d'abord) :
     • succès           → session ouverte.
     • refus de clé     → candidat suivant.
     • rejet transitoire→ remonter (l'UI invite à re-présenter la carte).
5. Tous les candidats refusés :
     • document non-français → tenter BAC en dernier recours.
     • sinon → échec de la clé MRZ → l'UI propose alors le champ CAN.
```

Le CAN reste donc le **dernier** filet, après épuisement des candidats sur un vrai refus. Une
perte de contact ou un aléa NFC n'affiche **jamais** le champ CAN — seulement une invite à
re-présenter la carte, la clé MRZ étant conservée.
