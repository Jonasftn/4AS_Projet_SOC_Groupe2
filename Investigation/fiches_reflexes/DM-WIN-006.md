# Fiche réflexe — DM-WIN-006 : enfant inhabituel de WmiPrvSE

| | |
|---|---|
| **ID règle** | DM-WIN-006 |
| **Sévérité** | MEDIUM |
| **ATT&CK** | T1047 — Windows Management Instrumentation |
| **Étape Kill Chain** | Mouvement latéral / exécution |
| **SLA** | Qualification < 8h |

## Ce que l'alerte signifie
Un processus enfant de `wmiprvse.exe` a été créé **sans** la redirection de sortie vers `127.0.0.1`. Cela couvre les exécutions WMI distantes qui ne récupèrent pas la sortie — notamment `wmiexec.py -silentcommand` — ainsi que d'autres usages WMI distants. C'est une règle plus large et moins spécifique que DM-WIN-005 : elle sert de filet pour les cas que la règle principale ne voit pas.

> Complémentarité : si une commande a la redirection `127.0.0.1`, c'est DM-WIN-005 (HIGH) qui se déclenche. Sinon, c'est cette règle. Les deux ne doivent pas doublonner.

## T0 — Analyse immédiate (0-5 min)
1. Identifier l'hôte (`ComputerName`), la session (`LogonId`) et les processus lancés (`images`, `commandes`).
2. Vérifier si un logon réseau (4624 type 3) correspond à la session, et depuis quelle IP.
3. Déterminer si l'activité correspond à un outil d'administration connu (SCCM, supervision) ou non.

## Pivots d'investigation (Splunk)

**IP source de la session (P-LOGON-SESSION)**
```
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=3
| eval sess=lower(mvindex(Logon_ID, -1))
| search sess="<LogonId en minuscules>"
| table _time ComputerName Account_Name Source_Network_Address
```

**Arbre des processus de la session (P-PROC-TREE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 LogonId="<LogonId>"
| table _time ParentImage Image CommandLine
```

## Qualification
- **Vrai positif** : exécution WMI distante depuis une IP ou un compte inhabituel, sans contexte d'administration légitime.
- **Faux positif** : outils d'administration par WMI (SCCM, scripts planifiés, supervision), `WerFault.exe`, `ccmexec.exe`. Dans ce lab il n'y a aucun trafic WMI légitime (baseline vide), mais en production ces sources sont à ajouter à la lookup d'exclusion.

## Endiguement
- Si l'activité n'est pas reconnue : isoler l'hôte et désactiver le compte de la session.

## Remédiation
- Maintenir à jour la liste d'exclusion des outils d'administration légitimes.
- Vérifier la présence de persistance si l'exécution est confirmée malveillante.

## À ne pas faire
- Ne pas désactiver WMI globalement sans étude d'impact : de nombreux outils légitimes en dépendent.
