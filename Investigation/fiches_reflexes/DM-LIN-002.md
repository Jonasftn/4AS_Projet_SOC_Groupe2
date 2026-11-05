# DM-LIN-002 – Recherche de secrets et mots de passe

| Champ | Valeur |
|---|---|
| ID | DM-LIN-002 |
| Nom de l'alerte Splunk | [BUILD] [HIGH] Recherche de secrets et mots de passe |
| Sévérité | High  |
| MITRE ATT&CK | T1552 (Credential Access) |
| Statut | Validée de bout en bout (Kunai → Splunk → DFIR-IRIS) |

## Description

Détecte les commandes qui recherchent des mots de passe, clés ou fichiers de secrets sur le système, avec les outils natifs (`grep`, `find`, `cat`...) ou des outils dédiés (`LaZagne`, `trufflehog`, `gitleaks`, `mimipenguin`). 

## Pourquoi c'est important

La recherche de secrets locaux (clés SSH, tokens d'API, mots de passe en dur dans des scripts ou fichiers de configuration) est une étape critique de la phase de post-exploitation. Elle permet à l'attaquant de voler des identifiants valides pour élever ses privilèges ou préparer un déplacement latéral discret vers d'autres machines.

## Requête SPL

```spl
index=main sourcetype=kunai
| rex max_match=0 field=_raw "(?<obj>\{\"data\":.*?\"utc_time\":\"[^\"]+\"\}\})"
| mvexpand obj
| spath input=obj path=info.event.name output=ev
| search ev="execve"
| spath input=obj path=data.command_line output=cl
| spath input=obj path=info.host.name output=srv
| spath input=obj path=info.task.user output=usr
| eval cmd=cl
| where isnotnull(cmd)
| where (match(cmd, "(?i)^\s*(sudo\s+)?(/usr/bin/|/bin/)?(grep|egrep|fgrep|rg|find|locate|cat|less|more|head|tail|strings)\s.*(passw(or)?d\b|\bsecrets?\b|\btoken|api_key|id_rsa|id_ed25519|[.]kdbx|[.]pem\b|[.]git-credentials|[.]aws/credentials|bash_history|wp-config|[.]env\b)") AND NOT match(cmd, "(?i)(/etc/passwd|/etc/pam[.]d)")) OR match(cmd, "(?i)(^|/|\s)(lazagne|trufflehog|gitleaks|mimipenguin)([.]py)?(\s|$)")
| lookup DM-LIN-002_exclusions.csv user AS usr OUTPUT exclude
| where isnull(exclude)
| rename srv AS "info.host.name", usr AS "info.task.user", cl AS "data.command_line"
| table _time info.host.name info.task.user data.command_line
```

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, `*/5 * * * *` |
| Time Range | `earliest=-10m@m`, `latest=-5m@m` |
| Trigger | Number of Results > 0, For each result |
| Throttle | Suppress triggering for 30 minutes, fields: `info.host.name`, `info.task.user` |
| Action | Webhook → `http://soc_n8n:5678/webhook/alert` |

## Fiche réflexe

### Triage en 5 questions

1. **Qui** a lancé la commande ? S'agit-il d'un compte de service CI/CD  ou d'un utilisateur humain ?
2. **Où** : Sur quelle machine ? Est-ce un serveur hébergeant du code, des sauvegardes ou un environnement de développement critique ?
3. **Quoi** : Quel outil a été utilisé (natif vs outil de hacking dédié) ? Quel type de secret était ciblé (clé SSH, token API, mot de passe) ?
4. **Quand** : L'action correspond-elle à un déploiement planifié ou à un audit de sécurité autorisé ?
5. **Comment** : Quel est le processus parent ? (Pivoter sur `P-PROC-TREE`). S'agit-il d'un pipeline automatisé ou d'un shell interactif ?

### Faux positifs fréquents

- Scanners de secrets légitimes lancés par l'équipe DevOps (ex: `trufflehog` ou `gitleaks` dans un pipeline CI/CD).
- Scripts d'administration, de sauvegarde ou de conformité.
- Administrateurs systèmes cherchant légitimement un fichier de configuration.

### Actions

- **Faux Positifs** : Documenter dans IRIS, ajouter l'utilisateur ou le script au fichier `DM-LIN-002_exclusions.csv`. Clôturer l'alerte.
- **Suspect** : Analyser l'arborescence des processus (`P-PROC-TREE`) pour identifier l'origine de la commande. Vérifier les connexions SSH récentes (`P-USER-LOGONS`).
- **Malveillant** :
  - **Ne pas supprimer les fichiers consultés** avant d'avoir pu réaliser une copie forensique ou une collecte de preuves.
  - Isoler l'hôte compromis du réseau.
  - Identifier et révoquer immédiatement tous les secrets potentiellement exposés (clés SSH, tokens, mots de passe).
  - Lancer une analyse d'impact pour vérifier si les secrets volés ont déjà été utilisés ailleurs sur le réseau.

## Test de validation (lab)

Exécution des commandes `sudo find / -name id_rsa` et `sudo grep -ri password /` sur la machine cible Ubuntu équipée de Kunai. La règle extrait et analyse correctement les commandes malgré le découpage JSON, et ignore les faux positifs comme `cat /etc/passwd`. Résultat : alerte HIGH correctement reçue et parsée dans DFIR-IRIS.

## Limites

- Lecture directe d'un fichier sensible sans passer par un motif ou une extension listée dans la regex.
- Utilisation de binaires alternatifs pour lire ou copier les fichiers (ex: `scp`, `base64`, `python`, `awk`, `sed`).
- Commandes ofusquées ou encodées.
- Outils de hacking renommés avant leur exécution.