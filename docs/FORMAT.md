# Spécification binaire de TGLD Secure Archive

**Nom :** TGLD Secure Archive
**Extension :** `.tgds`
**Signature :** `TGDS`
**Version du format :** 1
**Statut :** Spécification technique en cours de validation
**Plateformes :** Android, Windows et Linux

---

## 1. Objectifs

TGDS est un conteneur binaire destiné au stockage sécurisé de fichiers.

Ses objectifs sont :

- Confidentialité des données.
- Authentification cryptographique.
- Protection des métadonnées.
- Prise en charge de plusieurs fichiers.
- Détection des modifications et des troncatures.
- Compatibilité entre les plateformes.
- Évolution contrôlée du format.

Aucune porte dérobée ne doit être intégrée.

## 2. Conventions binaires

- Tous les nombres multioctets sont encodés en Little-endian.
- Les offsets commencent à zéro.
- Les longueurs sont exprimées en octets.
- Les chaînes du manifest sont encodées en UTF-8.
- Les champs réservés doivent être égaux à zéro.
- Les longueurs provenant d'une archive doivent être validées avant toute allocation.
- Les lecteurs doivent refuser les versions non prises en charge.

## 3. Organisation générale

L'archive est constituée des éléments suivants :

1. En-tête principal.
2. Enveloppe cryptographique.
3. Enregistrement du manifest chiffré.
4. Enregistrements des blocs de données chiffrés.
5. Fin exacte du fichier après le dernier bloc.

La version 1 ne définit pas de marqueur de fin séparé. Le nombre de blocs annoncé dans l'en-tête et la fin exacte du fichier permettent de détecter les archives incomplètes ou contenant des données supplémentaires.

## 4. En-tête principal

L'en-tête occupe exactement 64 octets.

| Offset | Taille | Champ | Valeur ou règle |
|---:|---:|---|---|
| 0 | 4 | Magic | ASCII `TGDS` |
| 4 | 2 | Format version | 1 |
| 6 | 2 | Flags | 0 en version 1 |
| 8 | 4 | Header size | 64 |
| 12 | 16 | Archive ID | Identifiant aléatoire |
| 28 | 4 | Envelope size | 112 |
| 32 | 8 | Manifest ciphertext size | Taille exacte du texte chiffré |
| 40 | 4 | Chunk count | Nombre total de blocs |
| 44 | 4 | Max chunk size | 1 048 576 octets |
| 48 | 16 | Reserved | Tous les octets à zéro |

L'identifiant d'archive est généré avec le générateur cryptographique du système.

L'en-tête complet est authentifié indirectement par les enregistrements cryptographiques qui l'utilisent comme donnée associée.

Toute valeur de champ incompatible avec la version 1 doit provoquer le rejet de l'archive.

## 5. Enveloppe cryptographique

L'enveloppe occupe exactement 112 octets.

| Offset relatif | Taille | Champ |
|---:|---:|---|
| 0 | 2 | Envelope version |
| 2 | 2 | KDF identifier |
| 4 | 4 | Argon2 memory en Kio |
| 8 | 4 | Argon2 iterations |
| 12 | 4 | Argon2 parallelism |
| 16 | 16 | Salt |
| 32 | 24 | Nonce |
| 56 | 48 | Wrapped DEK |
| 104 | 8 | Reserved |

Valeurs de la version 1 :

- Envelope version : 1.
- KDF identifier : 1 pour Argon2id.
- DEK : 32 octets.
- Salt : 16 octets.
- Nonce : 24 octets.
- Wrapped DEK : 48 octets, tag d'authentification inclus.
- Chiffrement : XChaCha20-Poly1305.

Paramètres Argon2id de référence :

- Mémoire initiale : 65 536 Kio.
- Passages : 3.
- Parallélisme : 1.
- Version Argon2 : 1.3.

Les paramètres réellement utilisés sont enregistrés dans l'enveloppe.

Les lecteurs doivent appliquer une politique de limites avant de lancer Argon2id :

- Mémoire autorisée : 65 536 à 262 144 Kio.
- Passages autorisés : 3 à 10.
- Parallélisme autorisé : 1 à 4.

Un appareil peut refuser une archive si les ressources nécessaires dépassent sa politique locale. Il ne doit jamais réduire silencieusement les paramètres enregistrés.

L'authentification de la DEK doit être liée à l'identifiant de l'archive et aux paramètres de l'enveloppe par des données associées authentifiées.

## 6. Enregistrement du manifest

L'enregistrement du manifest commence immédiatement après l'enveloppe.

Structure :

| Offset relatif | Taille | Champ |
|---:|---:|---|
| 0 | 24 | Nonce |
| 24 | 8 | Ciphertext size |
| 32 | Variable | Ciphertext et tag |

La taille annoncée dans l'en-tête principal correspond à la taille du ciphertext, tag inclus, sans compter le nonce et le champ de longueur.

Le manifest en clair contient :

| Champ | Taille |
|---|---:|
| Magic `TGMF` | 4 octets |
| Manifest version | 2 octets |
| Flags | 2 octets |
| File count | 4 octets |
| Total chunk count | 4 octets |
| Entrées des fichiers | Variable |

Chaque entrée de fichier contient :

| Champ | Taille |
|---|---:|
| File ID | 16 octets |
| Path length | 2 octets |
| Media type length | 2 octets |
| Original size | 8 octets |
| File chunk count | 4 octets |
| Compression identifier | 2 octets |
| Flags | 2 octets |
| Chemin UTF-8 | Variable |
| Type MIME UTF-8 | Variable |

Le manifest est entièrement chiffré et authentifié.

Limites initiales :

- Manifest en clair : 64 Mio maximum.
- Nombre de fichiers : 100 000 maximum.
- Chemin : 4 096 octets maximum.
- Type MIME : 255 octets maximum.

Les chemins sont relatifs à la racine d'extraction. Les chemins absolus, traversées de répertoires, noms interdits et collisions doivent être rejetés ou traités selon une politique explicite et sûre.

## 7. Enregistrements des blocs

Les blocs sont stockés après le manifest.

Chaque enregistrement commence par un en-tête fixe de 60 octets.

| Offset relatif | Taille | Champ |
|---:|---:|---|
| 0 | 16 | File ID |
| 16 | 4 | Chunk index |
| 20 | 2 | Compression identifier |
| 22 | 2 | Flags |
| 24 | 4 | Original chunk size |
| 28 | 4 | Compressed size |
| 32 | 24 | Nonce |
| 56 | 4 | Ciphertext size |
| 60 | Variable | Ciphertext et tag |

La taille du ciphertext doit être égale à la taille compressée plus 16 octets pour le tag d'authentification.

La taille originale d'un bloc ne doit pas dépasser 1 048 576 octets.

Identifiants de compression :

- 0 : aucune compression.
- 1 : Zstandard.

La compression est toujours effectuée avant le chiffrement.

Chaque bloc utilise XChaCha20-Poly1305 et un nonce de 24 octets.

Les nonces doivent être uniques pour chaque opération de chiffrement sous une même clé. Le moteur doit utiliser un mécanisme de génération et de gestion qui empêche leur réutilisation accidentelle.

## 8. Données associées authentifiées

Les AAD doivent lier chaque élément chiffré à son contexte.

Pour l'enveloppe :

- Identifiant de l'archive.
- Version du format.
- Paramètres de dérivation.
- Sel.
- Identifiant du domaine cryptographique.

Pour le manifest :

- En-tête principal complet.
- Enveloppe complète.
- Identifiant du domaine cryptographique.

Pour chaque bloc :

- Identifiant de l'archive.
- Empreinte SHA-256 du ciphertext du manifest.
- En-tête complet du bloc.
- Identifiant du domaine cryptographique.

Les encodages AAD doivent être définis sans ambiguïté avant l'implémentation.

Une modification, substitution ou permutation de blocs doit provoquer un échec d'authentification ou de validation structurelle.

## 9. Limites globales

Limites initiales de la version 1 :

| Élément | Limite |
|---|---:|
| Taille d'un bloc original | 1 Mio |
| Taille du manifest en clair | 64 Mio |
| Nombre de fichiers | 100 000 |
| Taille d'un chemin | 4 Kio |
| Nombre total de blocs | 1 048 576 |
| Taille maximale théorique des données originales | 1 Tio |

Ces limites sont des plafonds du format, pas des objectifs de consommation mémoire.

Les lecteurs doivent traiter les blocs progressivement et éviter de charger toute l'archive en mémoire.

Les décompressions doivent être bornées par la taille originale annoncée et par les limites locales.

## 10. Changement de mot de passe

Le changement de mot de passe suit les opérations suivantes :

1. Authentifier l'ancienne enveloppe.
2. Récupérer la DEK.
3. Générer un nouveau sel.
4. Dériver une nouvelle KEK.
5. Protéger la même DEK avec la nouvelle KEK.
6. Remplacer l'enveloppe de manière atomique ou produire une nouvelle archive temporaire.

Les blocs de données ne sont pas rechiffrés.

## 11. Détection des erreurs

Le lecteur doit rejeter :

- Une signature incorrecte.
- Une version inconnue.
- Une taille incohérente.
- Un champ réservé non nul.
- Un paramètre KDF hors limites.
- Une enveloppe de taille incorrecte.
- Un manifest invalide.
- Un nombre de blocs incohérent.
- Un bloc tronqué ou supplémentaire.
- Un tag d'authentification invalide.
- Une archive contenant des octets inattendus après le dernier bloc.

Aucune donnée non authentifiée ne doit être présentée comme un contenu valide.

## 12. Compatibilité et évolution

La version du format est indépendante de la version du logiciel.

Une modification incompatible nécessite une nouvelle version du format.

Les lecteurs doivent refuser proprement les versions qu'ils ne comprennent pas.

Les champs réservés ne peuvent être réutilisés que dans une version qui définit explicitement leur nouvelle signification.

## 13. Statut de sécurité

Cette spécification constitue une proposition normative de TGDS v1.

Elle ne doit pas être considérée comme finalisée avant :

- La définition exacte des encodages AAD.
- La validation des limites et des paramètres KDF.
- La définition des règles d'écriture atomique.
- La revue du modèle de menace.
- Les tests d'interopérabilité.
- Un audit cryptographique indépendant.

Aucune archive produite par une implémentation expérimentale ne doit être considérée comme garantie sûre pour un usage de production.

---

## 12. Séparation cryptographique des clés

### 12.1 Clé principale

Chaque archive possède une clé principale DEK de 32 octets, générée
avec un générateur cryptographique sécurisé.

Cette clé est protégée par l'enveloppe cryptographique et n'est jamais
enregistrée en clair dans l'archive.

### 12.2 Dérivation des sous-clés

La séparation des usages repose sur HKDF-SHA256 (RFC 5869).

Paramètres :

- IKM : DEK de 32 octets.
- Salt HKDF : identifiant d'archive de 16 octets.
- Hash : SHA-256.
- Longueur de sortie : 32 octets.

Deux clés indépendantes sont dérivées :

- K_manifest : info = ASCII `TGLDS/V1/MANIFEST`.
- K_chunks : info = ASCII `TGLDS/V1/CHUNKS`.

Chaque clé est exclusivement réservée à son usage.

La DEK ne doit jamais être utilisée directement pour chiffrer
le manifeste ou les blocs de données.

## 13. Encodage normatif des AAD

Les AAD sont des séquences d'octets concaténées dans l'ordre
indiqué. Aucun séparateur implicite ni encodage textuel supplémentaire
n'est autorisé.

Les chaînes de domaine sont encodées en ASCII, sans octet NUL final.

### 13.1 AAD de l'enveloppe

Ordre exact :

1. ASCII `TGLDS/V1/ENVELOPE`
2. Identifiant d'archive : 16 octets.
3. Version du format : u16 little-endian.
4. Version de l'enveloppe : u16 little-endian.
5. Identifiant KDF : u16 little-endian.
6. Mémoire Argon2 : u32 little-endian.
7. Nombre d'itérations : u32 little-endian.
8. Parallélisme : u32 little-endian.
9. Sel Argon2 : 16 octets.

Le nonce, la clé enveloppée et les octets réservés ne sont
pas inclus dans cette AAD.

### 13.2 AAD du manifeste

Ordre exact :

1. ASCII `TGLDS/V1/MANIFEST`
2. En-tête principal complet : 64 octets.

Le contenu de l'enveloppe cryptographique est volontairement exclu.

Cette règle permet de modifier le mot de passe sans devoir
rechiffrer le manifeste ou les blocs de données.

### 13.3 AAD des blocs

Ordre exact :

1. ASCII `TGLDS/V1/CHUNK`
2. Identifiant d'archive : 16 octets.
3. Empreinte SHA-256 de l'enregistrement complet du manifeste.
4. En-tête du bloc : 60 octets.

L'enregistrement complet du manifeste correspond à la concaténation
du nonce, du champ de longueur u64 little-endian et du texte chiffré.

L'en-tête du bloc comprend tous ses champs, y compris le nonce
et la longueur du texte chiffré.

## 14. Gestion des nonces

Chaque opération XChaCha20-Poly1305 utilise un nonce de 24 octets
généré par un générateur cryptographique sécurisé.

Un nonce ne doit jamais être réutilisé avec la même clé.

Le générateur doit vérifier les nonces déjà produits pendant
la création d'une archive et régénérer un nonce en cas de collision.

Les nonces ne sont pas secrets et sont stockés dans l'archive.

Toute erreur de génération aléatoire entraîne l'arrêt de l'opération.

## 15. Écriture atomique des archives

La création d'une archive doit respecter les étapes suivantes :

1. Créer un fichier temporaire dans le même répertoire que la destination.
2. Utiliser une création exclusive afin d'éviter les collisions.
3. Écrire l'en-tête, l'enveloppe, le manifeste et les blocs.
4. Vider les tampons d'écriture.
5. Synchroniser les données sur le stockage lorsque le système le permet.
6. Vérifier la structure et l'authenticité des données écrites.
7. Renommer le fichier temporaire vers la destination finale de manière atomique.

Par défaut, une destination existante ne doit pas être écrasée.

En cas d'échec, le fichier temporaire doit être supprimé lorsque cela
est possible. L'archive finale ne doit jamais être présentée comme
valide si l'écriture est incomplète.

Les différences de comportement entre Android, Linux et Windows
devront être traitées dans l'implémentation multiplateforme.

## 16. Changement de mot de passe

Le changement de mot de passe suit cet ordre :

1. Lire et valider l'enveloppe existante.
2. Dériver l'ancienne KEK avec Argon2id.
3. Authentifier et récupérer la DEK.
4. Générer un nouveau sel cryptographique.
5. Dériver la nouvelle KEK.
6. Créer une nouvelle enveloppe protégeant la même DEK.
7. Construire une nouvelle archive temporaire.
8. Copier sans modification les enregistrements du manifeste et des blocs.
9. Vérifier la nouvelle archive.
10. Remplacer atomiquement l'ancienne archive.

Le changement de mot de passe ne doit pas modifier la DEK,
les clés dérivées, les nonces, le manifeste ou les blocs chiffrés.

L'en-tête principal doit rester identique.

## 17. Règles de validation supplémentaires

Un lecteur conforme doit notamment :

- Refuser les identifiants de version non pris en charge.
- Refuser les champs réservés non nuls en version 1.
- Vérifier les tailles avant toute allocation mémoire.
- Vérifier la cohérence des nombres de fichiers et de blocs.
- Refuser les nonces ou structures de taille incorrecte.
- Vérifier l'authenticité de chaque enregistrement chiffré.
- Vérifier les tailles après décompression.
- Refuser les données supplémentaires après le dernier bloc.
- Ne jamais exposer un contenu partiellement authentifié comme fichier valide.

La décompression doit être bornée par la taille originale déclarée
et par les limites du format.

## 18. Statut de validation

Ces règles constituent la base normative proposée pour TGDS v1.

Elles doivent encore faire l'objet :

- d'une revue cryptographique indépendante ;
- de tests d'interopérabilité ;
- de tests de robustesse face aux archives malformées ;
- de validations multiplateformes ;
- d'une analyse des performances sur appareils Android à mémoire limitée.

Le format ne doit pas être déclaré prêt pour la production avant
la réussite de ces validations.

---

## 19. Profils cryptographiques obligatoires

Cette section prévaut sur toute règle antérieure incompatible.

### 19.1 Profil Argon2id v1

Pour KDF ID 1, les paramètres sont obligatoirement :

- Algorithme : Argon2id.
- Version : 0x13.
- Mémoire : 65536 KiB.
- Itérations : 3.
- Parallélisme : 1.
- Sortie : 32 octets.

Toute autre combinaison est rejetée avant le lancement d'Argon2id.

Un futur profil devra utiliser un nouvel identifiant KDF.

### 19.2 Gestion des nonces

Les nonces XChaCha20-Poly1305 sont générés indépendamment
avec un CSPRNG et mesurent exactement 24 octets.

La réutilisation volontaire d'un nonce avec une même clé est interdite.

Le lecteur ne doit pas exiger le chargement de tous les nonces
en mémoire pour vérifier leur unicité.

La sécurité repose sur la génération aléatoire cryptographique
et sur la taille de 192 bits des nonces.

Toute erreur du générateur aléatoire interrompt immédiatement
l'opération cryptographique.

## 20. Validation des chemins

Les chemins du manifeste utilisent exclusivement `/`
comme séparateur portable.

Un chemin doit :

- Être relatif à la racine de l'archive.
- Être encodé en UTF-8 valide.
- Ne contenir aucun octet NUL.
- Ne contenir aucun segment vide, `.` ou `..`.
- Ne pas commencer par `/`.
- Ne pas contenir de séparateur `\`.
- Ne pas représenter un chemin de lecteur Windows ou UNC.
- Ne pas contenir de caractères de contrôle.
- Respecter la limite de 4096 octets.

Les chemins dupliqués sont interdits.

Les collisions après normalisation Unicode ou comparaison
insensible à la casse sur les systèmes concernés doivent être
détectées avant extraction.

L'extraction doit empêcher toute sortie du répertoire de destination,
y compris par le biais de liens symboliques.

## 21. Cohérence des blocs et décompression

Les blocs d'un fichier sont identifiés par son file_id
et par un index commençant à zéro.

Les index doivent être continus, sans doublon ni omission.

Le nombre de blocs observé doit correspondre exactement
au manifeste et à l'en-tête principal.

Un fichier vide possède zéro bloc.

Pour une compression désactivée, la taille compressée doit
être égale à la taille originale.

Pour Zstandard :

- La taille décompressée doit correspondre exactement à la taille originale.
- La décompression doit être limitée à cette taille.
- Les données supplémentaires ou les trames non autorisées sont rejetées.
- Une erreur de décompression invalide le fichier concerné.

Aucun fichier ne doit être livré comme valide avant
l'authentification de tous ses blocs.

## 22. Compatibilité entre spécification et implémentation

L'implémentation Rust devra respecter les règles suivantes :

- L'enveloppe doit recevoir l'identifiant d'archive et les paramètres KDF
  nécessaires à la construction de son AAD.
- La dérivation HKDF doit être indépendante de la fonction Argon2id.
- La DEK ne doit jamais être utilisée directement pour les données.
- Le changement de mot de passe doit préserver les octets du manifeste
  et des blocs chiffrés.
- Le changement de mot de passe ne doit pas modifier l'en-tête principal.
- Toute modification d'un champ authentifié doit provoquer un échec
  d'authentification.

Les tests devront couvrir les archives tronquées, les tailles incohérentes,
les chemins dangereux, les blocs manquants, les doublons et les données
ajoutées après la fin de l'archive.

