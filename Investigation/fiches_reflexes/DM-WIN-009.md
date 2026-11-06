# DM-WIN-009 – Exécution de LOLBin

| Champ | Valeur |
|---|---|
| ID | DM-WIN-009 |
| Nom de l'alerte Splunk | [BUILD] [MEDIUM] Utilisation de LOLBin pour telechargement ou execution |
| Sévérité | Medium |
| MITRE ATT&CK | T1218 – System Binary Proxy Execution ; T1197 – BITS Jobs |
| Statut | Validée de bout en bout (périmètre limité à bitsadmin) |

## Description

Détecte l'exécution de binaires Windows légitimes détournés (« Living Off the Land Binaries »), par exemple `bitsadmin.exe`, `certutil.exe`, `mshta.exe`, `regsvr32.exe`, à partir des événements de création de processus Sysmon (EventCode 1).

## Pourquoi c'est important

Ces outils sont signés Microsoft et présents partout : ils passent souvent sous les radars. Ils servent à télécharger des charges (`bitsadmin`, `certutil`), exécuter du code distant (`mshta`, `regsvr32`) ou contourner les listes d'applications autorisées.

## Requête SPL

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
((Image="*\\certutil.exe" CommandLine="*urlcache*") OR (Image="*\\mshta.exe" CommandLine="*http*")
OR (Image="*\\regsvr32.exe" CommandLine="*/i:http*") OR (Image="*\\bitsadmin.exe" CommandLine="*/transfer*"))
| table _time ComputerName User Image CommandLine ParentImage
```

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, `*/5 * * * *` |
| Time Range | `earliest=-10m@m`, `latest=-5m@m` |
| Trigger | Number of Results > 0, Once |
| Throttle | Suppress triggering for 1 hour |
| Action | Webhook → `http://soc_n8n:5678/webhook/alert` |

## Fiche réflexe

### Triage en 5 questions

1. Quelle est la **ligne de commande** complète ? Chercher une URL, un chemin de sortie temporaire, des options de téléchargement ou d'exécution.
2. Quel est le **processus parent** ? Un Office, un navigateur ou un script qui lance un LOLBin est très suspect.
3. Quel **utilisateur** : compte de service ou utilisateur standard ?
4. Que s'est-il passé **ensuite** : nouveau fichier, processus enfant, connexion sortante ?
5. L'usage est-il **attendu** (script d'administration documenté) ?

### Faux positifs fréquents

- `bitsadmin` utilisé par des mécanismes de mise à jour.
- `certutil` pour la gestion de certificats par l'IT.

### Actions

- Récupérer la ligne de commande et les hashes, vérifier l'URL ou le fichier de destination.
- Examiner les processus enfants et les connexions réseau associés.
- Escalader si le LOLBin télécharge ou exécute du contenu inattendu.

## Test de validation (lab)

Exécution de `bitsadmin` sur une machine du lab. Résultat : alerte reçue dans DFIR-IRIS.

## Limites

La configuration Sysmon du lab ne journalise pas `certutil`, `mshta` et `regsvr32`. Seul **`bitsadmin`** est testable. La couverture réelle dépend de la configuration Sysmon, qui devrait journaliser tous les binaires visés.
