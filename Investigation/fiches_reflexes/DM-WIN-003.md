# DM-WIN-003 – Clé de registre Run (persistance)

| Champ | Valeur |
|---|---|
| ID | DM-WIN-003 |
| Nom de l'alerte Splunk | <à compléter depuis le YAML> |
| Sévérité | <à compléter depuis le YAML> |
| MITRE ATT&CK | T1547.001 – Registry Run Keys / Startup Folder |
| Statut | Validée de bout en bout (Splunk → DFIR-IRIS) |

## Description

Détecte l'ajout ou la modification d'une valeur dans les clés de démarrage automatique (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` et équivalents, dont `HKLM`). Le programme référencé se lance à l'ouverture de session.

## Pourquoi c'est important

Technique de persistance simple, qui ne demande pas toujours de droits élevés (côté `HKCU`) et reste discrète parmi les nombreuses entrées légitimes.

## Requête SPL

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 (TargetObject="*\\CurrentVersion\\Run\\*" OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
NOT Image="C:\\Program Files\\*" NOT Image="C:\\Program Files (x86)\\*" NOT Image="*\\msiexec.exe"
| eval severity_hint=if(match(Details, "(?i)(powershell|cmd|mshta|rundll32|wscript|cscript|\\\\Users\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\)"), "HIGH", "MEDIUM")
| table _time ComputerName User Image TargetObject Details severity_hint
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

1. Quelle **valeur** a été ajoutée (nom et donnée) ? Pointe-t-elle vers un chemin inhabituel (`\Temp\`, `\AppData\`, `\Users\Public\`) ?
2. Quel **processus** a écrit la clé (champ Image Sysmon) ? Un installateur connu ou `cmd.exe`, `powershell.exe`, `reg.exe` ?
3. Quel **utilisateur**, sur quelle machine ?
4. Le binaire référencé existe-t-il, est-il signé, quel est son hash ?
5. Y a-t-il une activité suspecte juste avant (téléchargement, exécution de script) ?

### Faux positifs fréquents

- Installation de logiciels légitimes (messagerie, clients cloud, pilotes).
- Mises à jour d'applications qui réécrivent leur entrée Run.

### Actions

- **Bénin** : noter l'application concernée, clôturer.
- **Suspect** : sauvegarder la valeur et le binaire avant toute suppression, analyser le hash, examiner les connexions réseau du processus.
- **Malveillant** : escalader, supprimer l'entrée après collecte des preuves, rechercher d'autres persistances (tâches, services).

## Test de validation (lab)

Ajout d'une valeur dans la clé Run sur une machine du lab. Résultat : alerte reçue dans DFIR-IRIS.

## Limites

- Délai de détection de 5 à 10 minutes dû à la fenêtre décalée.
- Détection basée sur des motifs : contournable via d'autres emplacements de persistance.
