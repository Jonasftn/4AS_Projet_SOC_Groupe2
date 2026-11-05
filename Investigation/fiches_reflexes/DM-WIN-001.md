# DM-WIN-001 – Création d'une tâche planifiée suspecte

| Champ | Valeur |
|---|---|
| ID | DM-WIN-001 |
| Nom de l'alerte Splunk | [BUILD] [MEDIUM] Creation d'une tache planifiee suspecte |
| Sévérité | Medium |
| MITRE ATT&CK | T1053.005 – Scheduled Task/Job: Scheduled Task |
| Statut | Validée de bout en bout (Splunk → DFIR-IRIS) |

## Description

Détecte la création d'une tâche planifiée Windows (par exemple via `schtasks /create`) présentant des caractéristiques suspectes. Mécanisme classique de persistance, d'exécution différée et de mouvement latéral.

## Pourquoi c'est important

Une tâche planifiée survit au redémarrage, peut s'exécuter sous SYSTEM et relance le code de l'attaquant à intervalle régulier. Elle peut aussi être créée à distance.

## Requête SPL

```
index=main ((source="WinEventLog:Security" EventCode=4698) OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"))
| eval detail=coalesce(Task_Content, CommandLine)
| where match(detail, "(?i)(powershell|cmd\.exe\s+/c|mshta|rundll32|regsvr32|\\\\AppData\\\\|\\\\Temp\\\\|\\\\Users\\\\Public|-enc|http)")
| table _time ComputerName User detail
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

1. **Qui** a créé la tâche (compte, session) ? Compte administrateur légitime ou inhabituel ?
2. **Où** : sur quelle machine ? Un DC ou un serveur critique aggrave la gravité.
3. **Quoi** : quelle commande ou quel binaire la tâche lance-t-elle ? Chercher `cmd /c`, `powershell`, chemins `\Temp\`, `\AppData\`, `\Users\Public\`.
4. **Quand** : heure de maintenance habituelle ou hors horaires ?
5. **Pourquoi** : un ticket de changement ou un déploiement logiciel l'explique-t-il ?

### Faux positifs fréquents

- Tâches créées par des logiciels légitimes (mises à jour, antivirus, sauvegarde).
- Scripts d'administration planifiés par l'équipe IT.

### Actions

- **Bénin confirmé** : documenter la raison dans IRIS, clôturer.
- **Suspect** : récupérer le détail (`schtasks /query /tn <nom> /v /fo list`), identifier le processus parent, chercher d'autres événements du même utilisateur et de la même machine sur ±1 h.
- **Malveillant** : escalader, isoler la machine selon la procédure, supprimer la tâche seulement après collecte des preuves.

## Test de validation (lab)

Création d'une tâche avec `schtasks /create` sur une machine du lab, en veillant à ce que l'événement tombe dans la fenêtre -10m@m / -5m@m du passage de cron. Résultat : alerte reçue dans DFIR-IRIS.

## Limites

- Délai de détection de 5 à 10 minutes dû à la fenêtre décalée.
- Un événement hors de la fenêtre d'un passage de cron est manqué par ce passage.
