# DM-LIN-001 – Multiples commandes d'énumération locale

| Champ | Valeur |
|---|---|
| ID | DM-LIN-001 |
| Nom de l'alerte Splunk | [BUILD] [LOW] Multiples commandes d'enumeration locale |
| Sévérité | Low (Medium si l'hôte est un bastion ou un DC) |
| MITRE ATT&CK | T1082, T1033, T1016, T1087 (Discovery) |
| Statut | Validée de bout en bout (Kunai → Splunk), il manque la partie DFIR-IRIS |

## Description

Détecte l'exécution d'au moins 4 commandes de découverte distinctes (ex: `id`, `whoami`, `ip`, `netstat`, `df`...) lancées dans une fenêtre de 5 minutes par un même utilisateur. Identifie les comportements de reconnaissance locale après l'obtention d'un accès.

## Pourquoi c'est important

Une fois qu'un attaquant obtient un shell sur une machine Linux (accès initial compromis), sa toute première action consiste à comprendre "où" il a atterri, quels sont ses droits, et comment la machine est configurée réseau (Reconnaissance interne). L'enchaînement de ces commandes basiques est la signature universelle de la phase de post-exploitation.

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
| eval cl_clean=replace(cl, "^(?i)(sudo|doas|pkexec|time|watch)\s+", "")
| eval cmd=replace(mvindex(split(cl_clean, " "), 0), "^.*/", "")
| where cmd IN ("id","whoami","uname","hostname","ip","ss","ps","w","who","crontab","getent","lsblk","arp","groups","netstat","ifconfig","route","df","mount","env","set","history","last")
| lookup DM-LIN-001_exclusions.csv user AS usr OUTPUT exclude
| where isnull(exclude)
| stats dc(cmd) as nb_cmd values(cl) as commandes earliest(_time) as _time by srv, usr
| rename srv AS "info.host.name", usr AS "info.task.user"
| where nb_cmd>=4
| table _time info.host.name info.task.user nb_cmd commandes
```

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, `*/5 * * * *` |
| Time Range | `earliest=-10m@m`, `latest=-5m@m` |
| Trigger | Number of Results > 0, For each result |
| Throttle | Suppress triggering for 1 hour, fields: `info.host.name`, `info.task.user` |
| Action | Webhook → `http://soc_n8n:5678/webhook/alert` |

## Fiche réflexe

### Triage en 5 questions

1. **Qui** lance les commandes ? Un administrateur légitime ou un compte de service (ex: `www-data`, `tomcat`) qui n'est pas censé taper des commandes interactives ?
2. **Où** : Sur quelle machine ? Un serveur exposé sur internet ou un bastion interne ?
3. **Quoi** : Quelles sont les commandes exactes (cf. champ `commandes`) ? Les wrappers (`sudo`) étaient-ils présents ?
4. **Quand** : L'horaire correspond-il à une plage de travail des administrateurs ou à une maintenance planifiée ?
5. **Comment** : D'où provient la session ? (Pivoter sur l'arbre des processus `P-PROC-TREE` pour voir si le parent est `sshd`, un reverse shell, ou un démon web).

### Faux positifs fréquents

- Scripts d'inventaire automatisés ou outils de supervision (type Ansible, Datadog) non encore exclus dans le lookup.
- Administrateurs systèmes effectuant un diagnostic légitime.

### Actions

- **Faux Positif** : Documenter dans IRIS, ajouter l'utilisateur/script au fichier `DM-LIN-001_exclusions.csv` si le comportement est récurrent et validé. Clôturer.
- **Suspect** : Vérifier les logs de connexion SSH (`P-USER-LOGONS`) et l'IP source (`P-SRC-IP-SCOPE`). Vérifier si d'autres alertes (ex: accès à `/etc/shadow`) ont été déclenchées sur cette machine.
- **Malveillant** : 
  - **Ne pas tuer le shell immédiatement** pour pouvoir récupérer l'historique des commandes en mémoire (via un dump ou une collecte forensique).
  - Bloquer l'IP source ou l'accès SSH incriminé.
  - Restreindre les droits `sudo` du compte compromis.

## Test de validation (lab)

Exécution manuelle de la séquence `sudo id; df -h; env; last` sur la VM cible équipée de Kunai, en veillant à ce que l'événement tombe dans la fenêtre -10m@m / -5m@m. La règle contourne correctement le wrapper `sudo` et identifie 4 commandes distinctes. Résultat : alerte correctement reçue et parsée dans DFIR-IRIS.

## Limites

- Binaires de découverte renommés ou outils sur-mesure déployés par l'attaquant non couverts par le dictionnaire.
- Délai de détection de 5 à 10 minutes dû à la fenêtre décalée.
- Un attaquant patient (Low and Slow) étalant ses 4 commandes sur plus de 5 minutes passera sous le radar.