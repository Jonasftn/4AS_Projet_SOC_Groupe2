# DM-LIN-003 – Accès à /etc/shadow

| Champ | Valeur | 
| ----- | ----- | 
| ID | DM-LIN-003 | 
| Nom de l'alerte Splunk | \[BUILD\] \[HIGH\] Acces a /etc/shadow | 
| Sévérité | High  | 
| MITRE ATT&CK | T1003 (OS Credential Dumping) | 
| Statut | Validée de bout en bout (Kunai → Splunk → DFIR-IRIS) | 

## Description

Détecte la lecture ou la copie des fichiers contenant les empreintes (hash) de mots de passe locaux, principalement `/etc/shadow` (mais aussi `gshadow` et leurs sauvegardes), par une commande utilisateur. La règle couvre les tentatives de dissimulation via des chemins déguisés (ex: `/etc//shadow`), des wildcards ou des accès relatifs.

## Pourquoi c'est important

Le fichier `/etc/shadow` contient les hashs des mots de passe des utilisateurs locaux (y compris root). S'il est lu ou exfiltré, un attaquant peut réaliser une attaque par force brute (cracking) hors-ligne (ex: avec Hashcat ou John the Ripper) pour retrouver les mots de passe en clair. C'est une étape critique pour l'élévation de privilèges ou le maintien d'accès. L'attaquant doit généralement déjà posséder les droits root pour réussir cette lecture.

## Requête SPL

```spl
index=main sourcetype=kunai
| rex max_match=0 field=_raw "(?<obj>\{\"data\":.*?\"utc_time\":\"[^\"]+\"\}\})"
| mvexpand obj
| spath input=obj path=info.event.name output=ev
| search ev="execve"
| spath input=obj path=data.command_line output=cl
| search cl="*shadow*" OR cl="*/etc/*"
| spath input=obj path=info.host.name output=srv
| spath input=obj path=info.task.user output=usr
| eval cmd=cl
| where isnotnull(cmd)
| where match(cmd, "(?i)(/etc/+([.]?/+)*|/var/backups/)g?shadow") OR match(cmd, "(?i)/etc/+([.]?/+)*g?(s|sh|sha|shad|shado)[*?[]") OR match(cmd, "(?i)(^|[/\s])(cat|cp|less|more|head|tail|strings|base64|xxd|dd|sed|awk|grep|tar|unshadow|john)\s([^|;&]*[\s=])?g?shadow-?(\s|$)")
| lookup DM-LIN-003_exclusions.csv user AS usr OUTPUT exclude
| where isnull(exclude)
| rename srv AS "info.host.name", usr AS "info.task.user", cl AS "data.command_line"
| table _time info.host.name info.task.user data.command_line
```

## Paramètres de l'alerte

| Champ | Valeur | 
| ----- | ----- | 
| Permissions | Shared in App | 
| Alert type | Scheduled, `*/5 * * * *` | 
| Time Range | `earliest=-10m@m`, `latest=-5m@m` | 
| Trigger | Number of Results > 0, For each result | 
| Throttle | Suppress triggering for 1 hour, fields: `info.host.name` | 
| Action | Webhook → `http://soc_n8n:5678/webhook/alert` | 

## Fiche réflexe

### Triage en 5 questions

1. **Qui** a accédé au fichier ? S'agit-il du compte root légitime, d'un administrateur utilisant sudo, ou d'un service compromis ?

2. **Où** : Sur quelle machine ? Est-ce un serveur d'authentification (ex: LDAP/FreeIPA) ou un serveur de base de données isolé ?

3. **Quoi** : Quelle commande exacte a été saisie ? S'agit-il d'un simple affichage (`cat`), d'une copie (`cp`, `tar`) ou d'un outil de cracking direct (`unshadow`) ?

4. **Quand** : L'accès a-t-il eu lieu lors d'une opération de maintenance ou de sauvegarde système ?

5. **Comment** : D'où vient la session utilisateur ? (Pivoter sur `P-PROC-TREE` pour vérifier le processus parent et `P-USER-LOGONS` pour tracer l'IP source).

### Faux positifs fréquents

* Outils d'audit de sécurité ou scanners de vulnérabilités légitimes.
* Scripts de sauvegarde automatisés ou outils de conformité lisant `/etc` ou `/var/backups`.
* Administrateurs listant ou cherchant des fichiers (`ls /etc/sh*`, `find`).

### Actions

* **Faux Positifs** : Documenter dans IRIS. Si c'est un script régulier (ex: backup), l'ajouter au fichier `DM-LIN-003_exclusions.csv`. Clôturer.

* **Suspect** : Analyser l'arbre des processus (`P-PROC-TREE`) pour déterminer le contexte de l'exécution. Vérifier si des outils d'exfiltration (nc, curl, wget) ont été utilisés juste après.

* **Malveillant** :
  * **Ne pas modifier /etc/shadow** avant la collecte de preuves (pour préserver les horodatages MAC).
  * Isoler immédiatement la machine compromise du réseau.
  * Forcer la rotation (changement) de **tous** les mots de passe des comptes locaux de cette machine, car les hashs sont considérés comme compromis.
  * Vérifier la robustesse de la politique de mots de passe locale.

## Test de validation (lab)

Exécution des commandes `sudo cat /etc/shadow` et `cd /etc && sudo cat shadow` sur la VM cible de test équipée de Kunai. La règle gère correctement le découpage JSON, filtre intelligemment avec les mots-clés initiaux pour la performance, et identifie les accès directs ainsi que les chemins relatifs ou dissimulés (`/etc//shadow`). Résultat : alerte HIGH correctement reçue et parsée dans DFIR-IRIS.

## Limites

* Redirection gérée par le shell (ex: `cat < /etc/shadow`) où le chemin n'apparaît pas en argument dans `execve`.
* Chemin construit dynamiquement, variable ou encodé (ex: `base64`, concaténation dans python/bash).
* Lecture effectuée par un programme déjà compilé ou un processus en cours d'exécution (sans faire appel à un nouvel `execve`).
* Wildcard trop générique (ex: `cat /etc/*`), non détecté pour éviter de saturer le SIEM de faux positifs.