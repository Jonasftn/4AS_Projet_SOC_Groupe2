# Fiche réflexe — DM-WIN-005 : Impacket WMIExec

| | |
|---|---|
| **ID règle** | DM-WIN-005 |
| **Sévérité** | HIGH (CRITICAL si la cible est un DC) |
| **ATT&CK** | T1047 — Windows Management Instrumentation |
| **Étape Kill Chain** | Mouvement latéral / exécution |
| **SLA** | Notification client < 2h, qualification < 4h |

## Ce que l'alerte signifie
Un processus enfant de `wmiprvse.exe` a exécuté une commande dont la sortie est redirigée vers un partage administratif en boucle locale (`\\127.0.0.1\<partage>\__<epoch>`). C'est la signature de `wmiexec.py` (Impacket) : un attaquant exécute des commandes à distance sur la machine via WMI, en se servant d'identifiants ou d'un hash d'administrateur local. C'est un mouvement latéral confirmé, pas une simple reconnaissance.

## T0 — Analyse immédiate (0-5 min)
1. Identifier l'hôte cible (`ComputerName`), le compte utilisé (`user`) et la session (`LogonId`).
2. Récupérer l'IP source de l'attaquant (`src_ip`) — c'est la machine depuis laquelle part l'attaque.
3. Lister les commandes exécutées (`commandes`) pour évaluer ce que l'attaquant a fait.
4. Vérifier le caractère privilégié du compte : si c'est un compte admin du domaine ou sur un DC → escalade immédiate en CRITICAL.

## Pivots d'investigation (Splunk)

**Toute l'activité de la session attaquante (P-LOGON-SESSION)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 LogonId="<LogonId>"
| table _time Image CommandLine ParentImage
```

**Portée de l'IP source — autres hôtes touchés (P-SRC-IP-SCOPE)**
```
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=3 Source_Network_Address="<src_ip>"
| stats values(ComputerName) as hotes_touches count by Source_Network_Address
```

**Arbre des processus lancés sur l'hôte cible (P-PROC-TREE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ComputerName="<ComputerName>"
| table _time ParentImage Image CommandLine User
```

## Qualification
- **Vrai positif de sécurité** : exécution WMI distante non reconnue, compte admin, IP source inhabituelle.
- **Faux positif** : outil d'administration légitime utilisant la même mécanique de redirection. Rare — à confirmer avec le client. Si confirmé, ajouter l'hôte/compte à la lookup d'exclusion.

## Endiguement
- Isoler l'hôte cible **et** l'hôte source (l'IP de la session) du réseau.
- Désactiver ou réinitialiser le compte utilisé.
- Bloquer SMB (445) et RPC (135) depuis l'IP source au pare-feu.

## Remédiation
- Rechercher les autres hôtes touchés par la même IP source (pivot ci-dessus).
- Rotation des mots de passe des comptes administrateur exposés.
- Vérifier qu'aucune persistance n'a été posée (tâches, services, clés Run) via les règles DM-WIN-001/002/003.

## À ne pas faire
- Ne pas supprimer les fichiers `__<epoch>` sur l'hôte avant collecte : ils contiennent la sortie des commandes de l'attaquant.
- Ne pas éteindre l'hôte avant d'avoir recueilli les preuves.
