# DM-WIN-002 – Création d'un service suspect

| Champ | Valeur |
|---|---|
| ID | DM-WIN-002 |
| Nom de l'alerte Splunk | [BUILD] [HIGH] Creation d'un service suspect |
| Sévérité | High |
| MITRE ATT&CK | T1543.003 – Windows Service ; T1569.002 – Service Execution (smbexec) |
| Statut | Validée de bout en bout (Splunk → DFIR-IRIS) |

## Description

Détecte la création d'un service Windows dont le chemin d'exécutable correspond à des motifs typiques d'attaque. Lors des tests, la règle a détecté **smbexec** sur le contrôleur de domaine, avec son motif caractéristique : `%COMSPEC%`, partage `C$` et nom de service aléatoire (ex. `ZTEUUaeU`).

## Requête SPL

```
index=main ((source="WinEventLog:System" EventCode=7045) OR (source="WinEventLog:Security" EventCode=4697))
| eval svc_path=Service_File_Name
| where match(svc_path, "(?i)(%COMSPEC%|cmd(\.exe)?\s+/c|powershell|\\\\\\\\127\.0\.0\.1\\\\|\\\\ADMIN\$|\\\\Temp\\\\|\\\\AppData\\\\|\\\\Users\\\\Public|\\\\Windows\\\\[A-Za-z]{8}\.exe)")
| table _time ComputerName Service_Name svc_path Service_Account
```

Si l'échappement des antislashs diffère dans ton Splunk, reprends la version de ton YAML.

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, `*/5 * * * *` |
| Time Range | `earliest=-10m@m`, `latest=-5m@m` |
| Trigger | Number of Results > 0, Once |
| Throttle | Suppress triggering for 1 hour |
| Action | Webhook → `http://soc_n8n:5678/webhook/alert` |

## Pourquoi deux événements pour un seul service

Windows journalise la création d'un service à deux endroits :

- **EventCode 7045** (journal System) : généré par le Service Control Manager, toujours actif.
- **EventCode 4697** (journal Security) : généré uniquement si l'audit « Security System Extension » est activé (cas du DC).

L'OR est voulu : si l'audit Security est désactivé sur une machine, 7045 couvre la détection. Pour voir la source de chaque ligne, ajouter `source` au `table`.

## Fiche réflexe

### Triage en 5 questions

1. Le nom du service est-il aléatoire (8 caractères sans sens) ? Typique de smbexec ou d'un PsExec modifié.
2. Le chemin contient-il `%COMSPEC%`, `cmd /c`, `powershell`, `127.0.0.1` ou un partage administratif (`ADMIN$`, `C$`) ?
3. Le compte de service est-il `LocalSystem` sans raison légitime ?
4. Y a-t-il eu une authentification réseau (Event 4624, type 3) vers cette machine juste avant ? Indice de mouvement latéral.
5. Le service existe-t-il encore ? smbexec le supprime généralement très vite.

### Faux positifs fréquents

- Installateurs légitimes créant un service temporaire.
- Outils d'administration à distance autorisés (PsExec utilisé par l'IT).

### Actions

- Traiter en **priorité** (High), surtout sur un DC.
- Identifier la machine source et le compte utilisé ; chercher les mêmes indicateurs sur d'autres machines.
- Escalader sans attendre en cas de doute.
- Réinitialiser les identifiants du compte compromis selon la procédure.

## Test de validation (lab)

Exécution de smbexec depuis une machine du lab vers le DC. Résultat : alerte reçue dans DFIR-IRIS.

## Limites et écarts conception / implémentation

- **Throttle** : le YAML prévoyait un groupage par `ComputerName,Service_Name`. Dans Splunk 8.0.2, l'interface ne propose que « Suppress triggering for », sans « Fields to group by ». Le throttle s'applique à toute l'alerte pendant 1 heure : une seule alerte même si plusieurs machines sont touchées dans l'heure.
- **Doublon 7045/4697** : un `| dedup ComputerName, Service_Name` l'éliminerait ; il n'a pas été appliqué, la requête reste celle d'origine.
