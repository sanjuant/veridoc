Modèle OCR-B / MRZ pour Tesseract
=================================

Fichier   : mrz.traineddata
Rôle      : reconnaissance de la police OCR-B des bandes MRZ (moteur LSTM Tesseract 5).
Taille    : 1 452 847 octets
SHA-256   : ece2a54f125a73792f9cec74e6f8e62f6e5e00c7f19153ba865af689be5b5f01

Provenance
----------
Source : https://github.com/DoubangoTelecom/tesseractMRZ  (tessdata_fast/mrz.traineddata)
Licence: BSD-3-Clause — Copyright (c) 2019, DoubangoTelecom. All rights reserved.

Choix de ce modèle plutôt que d'autres :
  - Shreeshrii/tessdata_ocrb : PAS de fichier de licence -> non redistribuable, écarté.
  - DaanVanVugt/tesseract-mrz : GPL-3.0 -> incompatible avec une distribution libre, écarté.
  - Doubango : BSD-3-Clause, redistribuable, modèle « fast » (LSTM entier) ~1,4 Mo.

Interim : ce modèle communautaire est un point de départ à VALIDER sur des spécimens
FICTIFS/consentis de CNIe et passeports FR (jamais une vraie pièce de tiers = PII).
À terme, envisager un ré-entraînement 100 % maîtrisé (unicharset MRZ 37 glyphes) via
tesstrain (Apache-2.0) pour une provenance sans ambiguïté.

Chargement à l'exécution
------------------------
Copié une fois de assets/tessdata/ vers filesDir/tessdata/ (Tesseract exige un chemin
fichier réel). Voir TesseractOcrEngine.kt.
