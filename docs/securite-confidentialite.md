# Sécurité & confidentialité

Veripuce traite des **données personnelles sensibles** (identité, photo, adresse). Sa conception
est *local-first*, et cette garantie est **vérifiable techniquement**, pas seulement promise.

- [1. 100 % on-device](#1-100--on-device)
- [2. Floutage des données lues](#2-floutage-des-données-lues)
- [3. Le rapport de diagnostic caviardé](#3-le-rapport-de-diagnostic-caviardé)
- [4. Ancre de confiance CSCA](#4-ancre-de-confiance-csca)
- [5. Limites : EAC (DG3/DG4)](#5-limites--eac-dg3dg4)
- [6. Cadre d'usage (RGPD)](#6-cadre-dusage-rgpd)

---

## 1. 100 % on-device

**Aucune sortie réseau possible.** Les bibliothèques ML Kit/GMS injectent des permissions réseau
via la fusion de manifestes ; Veripuce les **retire explicitement** :

```xml
<!-- AndroidManifest.xml:12-13 -->
<uses-permission android:name="android.permission.INTERNET" tools:node="remove" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" tools:node="remove" />
```

Résultat : l'application est **techniquement incapable** de transmettre une donnée. Seules
permissions conservées : `NFC` (requise) et `CAMERA` (optionnelle). Vérifiable sur l'APK :
`aapt2 dump permissions veripuce.apk`.

**Aucun stockage de données personnelles.**
- `android:allowBackup="false"` — rien ne part dans les sauvegardes Android/cloud.
- Les seules données persistées sont un booléen (mode diagnostic) et un sel de corrélation
  aléatoire, dans des `SharedPreferences` privées — **aucune donnée d'identité**.
- **Aucune journalisation** : zéro `Log`/`println` dans tout le code de production.

**OCR embarqué et hors-ligne.** Le modèle ML Kit est *bundled* dans l'APK : les images caméra
sont analysées en mémoire et **jamais enregistrées** ; l'app fonctionne sans Play Services.

Tout ce qui est lu reste **en mémoire** et disparaît à la fermeture.

---

## 2. Floutage des données lues

À l'écran, les données sensibles (photo, identité, numéro, MRZ) sont **floutées par défaut** et
ne s'affichent que pendant l'appui sur un bouton **« Maintenir pour afficher »**. Utile en
agence, contre les regards par-dessus l'épaule.

- **Texte** — un `BlurMaskFilter` floute le *rendu* du `TextView` sans jamais modifier son
  contenu (`MainActivity.kt:637-645`).
- **Photo** — floutée par sous-échantillonnage (réduction ×14 puis ré-agrandissement),
  compatible toutes versions d'Android (`MainActivity.kt:648-656`).
- **Révélation en appui maintenu** — visible tant que le doigt reste posé (`ACTION_DOWN` →
  visible, `ACTION_UP`/`ACTION_CANCEL` → re-flouté) (`MainActivity.kt:667-680`).

---

## 3. Le rapport de diagnostic caviardé

Pour déboguer les cas où une carte bascule sur le CAN (voir [Calcul des clés](cles-acces.md)), un
**mode diagnostic** produit un rapport technique **partageable sans exposer de donnée personnelle**.

### Activation

Le mode est **désactivé par défaut**. Pour l'activer : **appui long sur le titre « Veripuce »**
en haut de l'écran (un message confirme). C'est **persistant** (reste actif après redémarrage,
jusqu'à un nouvel appui long). Une carte « Détails techniques » apparaît alors sur l'écran de
résultat et sur les échecs ; **Copier** / **Partager** exportent le rapport.

> Pour un test terrain, activer le mode **avant** de reproduire le problème : le collecteur ne
> tourne que quand le mode est actif (garantie « lecture strictement inchangée » sinon).

### Règles de caviardage

Le rapport est **caviardé à la construction** : l'objet `DebugReport` ne stocke que des dérivés
masqués (`DebugReport.kt:5-15`). Il n'existe **aucune fonction de dé-caviardage**. N'apparaissent
**jamais** : numéro de document complet, dates (seule l'année d'expiration est permise), CAN,
nom, MRZ brute, texte OCR, photo, contenu DG13.

| Donnée brute | Ce que le rapport montre |
|---|---|
| Numéro de document | un **motif** par classes (`L`=lettre, `9`=chiffre, `<`=remplissage) |
| Corrélation entre lectures | une **empreinte** `SHA-256(numéro + sel)` tronquée à 8 hex |
| Échec d'accès | un **status word** (`SW=0x6300`), `TagLost`, ou une classe d'exception — **jamais** le message |
| Tentative de clé | un libellé masqué : `MRZ`, `MRZ-candidat(pos=3)` (position seule), `CAN` |

### Budget global anti-reconstitution

Seule exception assumée : quelques caractères aux positions **ambiguës** ou **divergentes** (la
preuve directe d'une erreur OCR). Un plafond **global unique** garantit qu'on ne peut pas
reconstituer le numéro :

```
MAX_REVEALED_POSITIONS = 3        (DebugReport.kt:151)
```

Au plus **3 positions révélées sur 9** ⇒ au moins 6 inconnues ⇒ reconstitution impossible. Ce
plafond s'applique à l'**union** des sources (divergences prioritaires, puis ambiguïtés, sans
double compte).

> Cette valeur est le résultat d'un **audit anti-fuite adverse** (agents cherchant à reconstituer
> le numéro) : la version initiale utilisait deux plafonds indépendants (4 + 6 = 10 > 9) et
> permettait la reconstitution. Le budget global unique ferme la fuite ; un second audit l'a
> confirmé (`maxRealCharsRevealed = 3`, `reconstructionPossible = false`).

Le **sel de corrélation** (16 octets aléatoires par installation) sert uniquement à l'empreinte
et **ne quitte jamais l'appareil**. Copie et partage n'émettent que la sortie déjà caviardée de
`serialize()`.

---

## 4. Ancre de confiance CSCA

Le verdict « émis par l'État » repose sur les certificats CSCA embarqués (`CscaStore.kt`), décrits
en détail dans [Sources & données](sources.md). Points de sécurité :

- Le **vert** n'est accordé que si l'origine étatique est **prouvée** (`SignatureCheck.TRUSTED`) —
  un DSC auto-signé par un fraudeur reste `VALID_UNTRUSTED`.
- Sans certificat chargé, la signature reste vérifiée cryptographiquement mais l'origine ne peut
  pas être prouvée (jamais un faux « vert »).
- Au démarrage, le Bouncy Castle partiel d'Android est **remplacé** par la version complète
  (`Security.removeProvider("BC")` puis `addProvider`) pour couvrir toutes les courbes.

---

## 5. Limites : EAC (DG3/DG4)

Les données biométriques les plus sensibles — **DG3 (empreintes digitales)** et **DG4 (iris)** —
sont protégées par **EAC / Terminal Authentication** : leur lecture exige un certificat de
terminal délivré par l'État, qu'aucune application publique ne détient. Elles sont donc
**cryptographiquement inaccessibles**.

Veripuce ne les référence **jamais** : le lecteur ne sélectionne que DG1, DG2, DG13, DG14, DG15
et EF.SOD (`CnieReader.kt`). Les données biométriques restent hors de portée par conception.

---

## 6. Cadre d'usage (RGPD)

Lire une pièce d'identité traite des **données personnelles**. L'outil technique ne dispense pas
du cadre légal :

- **Consentement** de la personne concernée avant toute lecture.
- **Minimisation & non-conservation** : garanties techniquement par les points ci-dessus (pas de
  réseau, pas de stockage).
- **Finalité légitime** : n'utiliser l'application que dans un cadre autorisé (vérification
  d'identité en présence de la personne).

Un bandeau « 100 % local » dans l'application ouvre le détail de ces garanties à l'utilisateur.
