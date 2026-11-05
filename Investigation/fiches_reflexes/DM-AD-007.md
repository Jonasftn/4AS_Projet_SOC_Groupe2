# Fiche réflexe — DM-AD-007 : extraction de NTDS.dit

| | |
|---|---|
| **ID règle** | DM-AD-007 |
| **Sévérité** | CRITICAL |
| **ATT&CK** | T1003.003 — OS Credential Dumping: NTDS |
| **Étape Kill Chain** | Accès aux identifiants |
| **SLA** | Notification client < 2h, qualification < 4h |

## Ce que l'alerte signifie
Une tentative d'extraction de la base d'annuaire Active Directory (`NTDS.dit`) a été détectée sur le contrôleur de domaine. Cette base contient les hash de **tous** les comptes du domaine, y compris `krbtgt`. Une extraction réussie équivaut à une compromission totale du domaine (possibilité de Golden Ticket). C'est l'un des incidents les plus graves possibles.

## Techniques couvertes (branche ligne de commande)
- `ntdsutil` en mode IFM (`ac i ntds` → `ifm` → `create full`)
- `vssadmin create shadow` (copie via cliché instantané)
- `diskshadow`
- toute commande manipulant `ntds.dit`

> Limite de collecte de cet environnement : la branche « création du fichier `ntds.dit` » (EventCode 11) ne se déclenche pas, car le filtre FileCreate de Sysmon ne couvre pas l'extension `.dit`. La détection repose sur la ligne de commande (EventCode 1), qui couvre toutes les techniques réelles ci-dessus. Durcissement à proposer : ajouter `.dit` au module FileCreate de Sysmon.

## T0 — Analyse immédiate (0-5 min)
1. Confirmer qu'il s'agit du DC (`ComputerName`).
2. Identifier la technique utilisée (`CommandLine`) et le compte (`User`).
3. Vérifier si une opération de sauvegarde légitime est en cours (certaines utilisent `vssadmin`).
4. CRITICAL par défaut → notification client immédiate et escalade.

## Pivots d'investigation (Splunk)

**Toute l'activité du compte sur le DC (P-USER-LOGONS)**
```
index=main ComputerName="<ComputerName>" (source="WinEventLog:Security" EventCode=4624) Account_Name="*<User>*"
| table _time Source_Network_Address Logon_Type
```

**Arbre des processus autour de l'événement (P-PROC-TREE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ComputerName="<ComputerName>"
| table _time ParentImage Image CommandLine User
```

**Recherche de persistance / exfiltration associée (P-PERSISTENCE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ComputerName="<ComputerName>" (EventCode=11 OR EventCode=3)
| table _time EventCode Image TargetFilename DestinationIp
```

## Qualification
- **Vrai positif** : utilisation de `ntdsutil`/`vssadmin`/`diskshadow` sur le DC hors fenêtre de sauvegarde planifiée, par un compte inattendu.
- **Faux positif** : sauvegarde système légitime du DC (certaines invoquent `vssadmin create shadow`). À exclure par compte/horaire de sauvegarde connu.

## Endiguement
- Isoler le DC du reste du réseau **après validation avec le client** (un DC isolé perturbe l'authentification du domaine).
- Désactiver le compte utilisé.

## Remédiation
- Double réinitialisation du mot de passe du compte `krbtgt` (procédure spécifique, avec délai entre les deux).
- Rotation des mots de passe de tous les comptes privilégiés.
- Rechercher toute copie de `ntds.dit` / `SYSTEM` créée et la supprimer de façon sécurisée.

## À ne pas faire
- Ne pas éteindre le DC sans consigne : risque de perte de preuves et d'indisponibilité du domaine.
- Ne pas réinitialiser `krbtgt` une seule fois : la procédure correcte demande deux réinitialisations espacées, sous peine de casser l'authentification ou de laisser une fenêtre à l'attaquant.
