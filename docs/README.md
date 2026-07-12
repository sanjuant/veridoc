# Documentation Veripuce

Documentation technique détaillée. Le [README principal](../README.md) donne la vue d'ensemble ;
ces fichiers approfondissent chaque sujet.

| Document | Contenu |
|---|---|
| [**Algorithmes**](algorithmes.md) | Pipeline OCR de la MRZ, parsing TD1/TD3, chiffres de contrôle ICAO, paires aveugles, vote par position, session PACE/BAC, *passive authentication* (intégrité + signature + chaîne CSCA), détection de puce clonée. |
| [**Calcul des clés d'accès**](cles-acces.md) | Comment la clé d'ouverture de la puce est dérivée (MRZ / CAN), la dérivation ICAO 9303-11, les candidats de clé sur paires aveugles, l'itération multi-protocoles PACE. |
| [**Sources & données**](sources.md) | Les certificats CSCA embarqués (ICAO + BSI + ANTS), le format auditable, le recoupement inter-canaux, le rafraîchissement automatique, les jeux de test cryptographiques. |
| [**Sécurité & confidentialité**](securite-confidentialite.md) | Modèle 100 % on-device, floutage des données lues, rapport de diagnostic caviardé, ancre de confiance CSCA, limites EAC. |

> Les références de code sont au format `Fichier.kt:ligne` — elles pointent la source faisant foi.
