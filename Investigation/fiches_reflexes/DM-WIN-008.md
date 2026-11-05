# Fiche réflexe — DM-WIN-008 : modification de la politique d'audit

| | |
|---|---|
| **ID règle** | DM-WIN-008 |
| **Sévérité** | HIGH (CRITICAL sur un DC) |
| **ATT&CK** | T1562.002 — Impair Defenses: Disable Windows Event Logging |
| **Étape Kill Chain** | Évasion de défense |
| **SLA** | Notification client < 2h, qualification < 4h |

## Ce que l'alerte signifie
La politique d'audit Windows a été modifiée (événement 4719) ou la commande `auditpol` a été utilisée avec `/set`, `/clear` ou `/remove`. Un attaquant qui **désactive** l'audit cherche à réduire la visibilité du SOC avant ou pendant son action. C'est un marqueur d'évasion de défense qui précède souvent une activité plus grave.

Le signal le plus fort est une **désactivation** : champ `Changes` contenant `removed` (ex. `Success removed, Failure removed`), ou `auditpol /success:disable`. Une activation (`Added`) est moins préoccupante mais reste à vérifier.

## T0 — Analyse immédiate (0-5 min)
1. Identifier l'hôte (`ComputerName`) et l'acteur (`actor`).
2. Déterminer le sens du changement : désactivation (`removed` / `disable`) = prioritaire, activation (`Added`) = à contextualiser.
3. Vérifier si le changement correspond à une opération d'administration planifiée et notifiée. Sinon → suspect.
4. Sur un DC → escalade en CRITICAL.

## Pivots d'investigation (Splunk)

**Activité du compte auteur (P-USER-LOGONS)**
```
index=main source="WinEventLog:Security" EventCode=4624 Account_Name="<actor>"
| table _time ComputerName Source_Network_Address Logon_Type
```

**Processus lancés par cet acteur autour de l'événement (P-PROC-TREE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ComputerName="<ComputerName>" User="*<actor>*"
| table _time ParentImage Image CommandLine
```

**Autres changements d'audit récents sur le parc**
```
index=main source="WinEventLog:Security" EventCode=4719
| stats count values(Changes) as changements by ComputerName, Account_Name
```

## Qualification
- **Vrai positif** : désactivation de l'audit par un compte ou à un moment non justifié, souvent suivie d'autres actions suspectes.
- **Faux positif** : application légitime d'une GPO d'audit (portée par `SYSTEM` ou un compte machine `$` — déjà exclus par la règle), ou opération d'administration planifiée et notifiée.

## Endiguement
- Restaurer la politique d'audit à son état attendu.
- Isoler l'hôte si la modification n'est pas reconnue.

## Remédiation
- Verrouiller la politique d'audit par GPO pour empêcher les modifications locales.
- Enquêter sur l'activité du compte auteur avant et après le changement.

## À ne pas faire
- Ne pas redémarrer l'hôte avant d'avoir restauré l'audit et collecté les preuves.
- Ne pas se fier uniquement aux journaux locaux de l'hôte : utiliser la copie centralisée dans Splunk, que l'attaquant ne peut pas modifier.
