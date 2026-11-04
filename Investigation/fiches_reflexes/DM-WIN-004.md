# Fiche réflexe — DM-WIN-004 : dump mémoire LSASS

| | |
|---|---|
| **ID règle** | DM-WIN-004 |
| **Sévérité** | CRITICAL |
| **ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Étape Kill Chain** | Accès aux identifiants |
| **SLA** | Notification client < 2h, qualification < 4h |

## Ce que l'alerte signifie
Une tentative d'extraction des identifiants depuis la mémoire du processus `lsass.exe` a été détectée. LSASS contient les mots de passe, hash et tickets Kerberos des sessions ouvertes. Un dump réussi permet à l'attaquant de récupérer ces secrets et de se déplacer latéralement. C'est un signal d'accès aux identifiants à traiter en urgence.

## Limite de collecte (propre à cet environnement)
L'EventCode 10 (ProcessAccess vers lsass) **n'est pas journalisé** par la configuration Sysmon de ce SI : le module ProcessAccess ne cible pas lsass.exe. La détection repose donc sur :
- **EventCode 1** : ligne de commande d'outils de dump (`comsvcs.dll MiniDump`, `procdump -ma lsass`) ;
- **EventCode 11** : création d'un fichier `*lsass*.dmp`.

Recommandation de durcissement à proposer au client : activer le module ProcessAccess sur lsass pour couvrir aussi les dumps en mémoire sans fichier ni ligne de commande évidente.

## T0 — Analyse immédiate (0-5 min)
1. Identifier l'hôte (`ComputerName`) et le processus à l'origine (`Image` / `SourceImage`).
2. Déterminer la méthode : ligne de commande (`CommandLine`) ou fichier dump créé (`TargetFilename`).
3. Identifier le compte ayant lancé l'action et vérifier s'il est privilégié.
4. CRITICAL par défaut → préparer la notification client immédiatement.

## Pivots d'investigation (Splunk)

**Processus parent et contexte (P-PROC-TREE)**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ComputerName="<ComputerName>"
| table _time ParentImage Image CommandLine User
```

**Sessions et comptes connectés sur l'hôte (P-LOGON-SESSION)** — tous ces comptes sont potentiellement compromis
```
index=main source="WinEventLog:Security" EventCode=4624 ComputerName="<ComputerName>*"
| stats values(Account_Name) as comptes by ComputerName
```

**Création de fichiers dump sur l'hôte**
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 ComputerName="<ComputerName>" TargetFilename="*.dmp"
| table _time Image TargetFilename
```

## Qualification
- **Vrai positif** : accès ou dump de lsass par un outil non légitime (procdump, comsvcs via rundll32, outil inconnu).
- **Faux positif** : antivirus / EDR qui accèdent légitimement à lsass, `WerFault.exe` lors d'un crash. À exclure par `SourceImage` dans la règle.

## Endiguement
- Isoler l'hôte du réseau immédiatement.
- Invalider les sessions de **tous** les comptes connectés à l'hôte (les secrets peuvent déjà être exfiltrés).

## Remédiation
- Réinitialiser les mots de passe de tous les comptes ayant eu une session sur l'hôte.
- Activer Credential Guard et la protection PPL de LSASS.
- Bloquer procdump / outils de dump via AppLocker ou l'EDR.

## À ne pas faire
- Ne pas éteindre l'hôte : la mémoire (et donc des preuves) serait perdue.
- Ne pas se contenter de réinitialiser le compte attaquant : tous les comptes de la machine sont concernés.
