# Spécification du format binaire TGLD Secure Archive

**Nom du format :** TGLD Secure Archive  
**Extension :** `.tgds`  
**Identifiant :** TGDS  
**Version de spécification :** 1  
**Statut :** Conception initiale  
**Plateformes cibles :** Android, Windows et Linux

---

## 1. Objectifs

Le format TGDS est un conteneur binaire destiné au stockage sécurisé de fichiers et de documents.

Il doit assurer :

- La confidentialité des données.
- L'authenticité des données chiffrées.
- La détection des modifications non autorisées.
- La protection des métadonnées.
- La prise en charge de plusieurs fichiers.
- L'évolution du format sans rupture inutile de compatibilité.

Aucune porte dérobée ne doit être intégrée au format.

## 2. Conventions binaires

Tous les champs numériques multioctets utilisent l'ordre Little-endian.

Les longueurs sont exprimées en octets, sauf indication contraire.

Les lecteurs doivent vérifier les longueurs avant toute allocation mémoire.

Les champs réservés doivent être initialisés à zéro dans cette version.

Un lecteur ne doit jamais interpréter une valeur inconnue comme une instruction valide.

## 3. Organisation générale

Une archive TGDS v1 est organisée dans l'ordre suivant :

1. En-tête principal.
2. Enveloppe de clé.
3. Manifest chiffré.
4. Séquence de blocs de données chiffrés.
5. Marqueur de fin.

## 4. En-tête principal

L'en-tête principal occupe exactement 32 octets.

| Décalage | Taille | Champ | Description |
|---:|---:|---|---|
| 0 | 4 | Magic | Signature ASCII `TGDS` |
| 4 | 2 | Version | Version du format : 1 |
| 6 | 2 | Header flags | Drapeaux définis par la version |
| 8 | 4 | Header size | Taille de l'en-tête : 32 |
| 12 | 16 | Archive ID | Identifiant aléatoire unique |
| 28 | 4 | Reserved | Valeur zéro |

Les lecteurs doivent rejeter les signatures incorrectes, les tailles invalides et les versions non prises en charge.

## 5. Enveloppe de clé

L'enveloppe protège la clé de données DEK.

Elle contient :

- Un identifiant d'algorithme.
- Les paramètres Argon2id.
- Un sel cryptographique de 16 octets.
- Un nonce XChaCha20-Poly1305 de 24 octets.
- La clé DEK chiffrée.
- Le tag d'authentification.

La DEK possède une taille de 32 octets.

Le résultat chiffré de la DEK possède une taille de 48 octets, tag inclus.

Les paramètres Argon2id doivent être enregistrés dans l'enveloppe afin de permettre leur évolution et la récupération des anciennes archives.

Les paramètres doivent être validés avant toute opération coûteuse de dérivation.

## 6. Manifest

Le manifest décrit le contenu de l'archive.

Il est entièrement chiffré et authentifié.

Il contient notamment :

- La version du manifest.
- Le nombre de fichiers.
- Les noms des fichiers.
- Les tailles originales.
- Les tailles compressées.
- Les identifiants des fichiers.
- Les informations de compression.
- Les références aux blocs de données.

Les chemins doivent être traités comme des données non fiables lors de l'extraction.

Les chemins absolus, les traversées de répertoires et les noms dangereux doivent être rejetés.

## 7. Blocs de données

Les fichiers sont découpés en blocs indépendants.

Chaque bloc possède :

- Un identifiant de fichier.
- Un index de bloc.
- Une longueur de données.
- Un nonce cryptographique.
- Un contenu chiffré.
- Un tag d'authentification.

Le chiffrement utilise XChaCha20-Poly1305.

La compression Zstandard intervient avant le chiffrement.

Chaque bloc doit être authentifié avant que son contenu soit utilisé.

Un nonce ne doit jamais être réutilisé avec la même clé.

## 8. Authentification des structures

Les données associées authentifiées (AAD) doivent lier les blocs à leur contexte.

Elles doivent inclure au minimum :

- L'identifiant de l'archive.
- La version du format.
- L'identifiant du fichier.
- L'index du bloc.
- Les longueurs attendues.

Le manifest doit également être lié à l'identifiant de l'archive et à sa version.

La modification d'un bloc, son déplacement ou son remplacement doit provoquer un échec d'authentification.

## 9. Marqueur de fin

Le marqueur de fin permet de détecter certaines archives tronquées ou incomplètes.

Il ne remplace pas l'authentification cryptographique.

La version 1 utilisera une structure de fin définie dans l'implémentation binaire.

## 10. Limites et protections

Les lecteurs doivent appliquer des limites configurables concernant :

- La taille totale de l'archive.
- La taille du manifest.
- Le nombre de fichiers.
- La taille maximale d'un bloc.
- Le nombre total de blocs.
- Les paramètres de dérivation Argon2id.
- La taille des données après décompression.

Aucune longueur provenant d'une archive ne doit être utilisée directement pour une allocation sans validation.

Les erreurs d'authentification ne doivent jamais exposer de données partiellement déchiffrées.

## 11. Changement de mot de passe

Le changement de mot de passe consiste à :

1. Récupérer la DEK avec l'ancien mot de passe.
2. Générer un nouveau sel.
3. Dériver une nouvelle KEK.
4. Protéger la DEK avec cette nouvelle KEK.
5. Remplacer l'ancienne enveloppe de manière sûre.

Les données déjà chiffrées ne sont pas rechiffrées.

## 12. Compatibilité

La version du format est indépendante de la version du logiciel.

Un lecteur doit refuser proprement une version qu'il ne comprend pas.

Les évolutions incompatibles nécessiteront une nouvelle version du format.

## 13. Statut de cette spécification

Cette documentation constitue une base de conception.

Les structures détaillées de l'enveloppe, du manifest, des blocs et du marqueur de fin devront être définies précisément avant leur implémentation.

Le format ne doit pas être considéré comme finalisé ni prêt pour une utilisation en production avant validation des spécifications, des tests de sécurité et un audit cryptographique indépendant.
