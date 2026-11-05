# Librairie de pivots

Chaque pivot répond à une question d'investigation précise, à partir d'un élément de l'alerte (hôte, compte, IP, processus, hash). Les identifiants sont ceux référencés dans le champ `investigation.pivots` des YAML de `Detection/`.

Les requêtes utilisent `index=main` (lab) ; il faudra le remplacer par l'index de production en RUN. Les valeurs entre chevrons (`<HOST>`, `<USER>`, …) sont à renseigner.

## Index

| ID | Question | Entrée | Source |
|---|---|---|---|
| [P-PROC-TREE](#p-proc-tree) | Qui a lancé ce processus et qu'a-t-il lancé ? | Hôte, ProcessGuid | Sysmon 1 |
| [P-LOGON-SESSION](#p-logon-session) | Qu'a fait cette session et d'où venait-elle ? | Hôte, LogonId | Security 4624 |
| [P-USER-LOGONS](#p-user-logons) | Où et comment ce compte s'est-il connecté ? | Compte | Security 4624, 4625, 4648 |
| [P-LOGON-SUCCESS](#p-logon-success) | Une source suspecte a-t-elle réussi à s'authentifier ? | IP | Security 4624 |
| [P-ACCOUNT-ACTIVITY](#p-account-activity) | Qu'a fait ce compte sur le périmètre ? | Compte | Toutes |
| [P-PRIV-USE](#p-priv-use) | Ce compte a-t-il utilisé des privilèges sensibles ? | Compte | Security 4672, 4673, 4674 |
| [P-SRC-IP-SCOPE](#p-src-ip-scope) | Qu'a fait cette IP sur tout le périmètre ? | IP | Toutes |
| [P-NET-CONN](#p-net-conn) | Avec qui cet hôte a-t-il communiqué ? | Hôte | Sysmon 3 |
| [P-DNS](#p-dns) | Quels domaines cet hôte a-t-il résolus ? | Hôte | Sysmon 22 |
| [P-PERSISTENCE](#p-persistence) | L'attaquant a-t-il installé une persistance ? | Hôte | Security 4698, 4697, System 7045, Sysmon 13 |
| [P-HASH-SCOPE](#p-hash-scope) | Ce binaire est-il présent ailleurs ? | Hash | Sysmon 1 |
| [P-KERBEROS-TGS](#p-kerberos-tgs) | Quels tickets de service ce compte a-t-il demandés ? | Compte | Security DC 4769 |
| [P-PKINIT-AUTH](#p-pkinit-auth) | Ce compte s'est-il authentifié par certificat (PKINIT) ? | Compte | Security DC 4768 |
| [P-DC-REPLICATION](#p-dc-replication) | Un compte non-DC a-t-il demandé une réplication d'annuaire ? | Compte | Security DC 4662 |
| [P-AD-OBJECT-HISTORY](#p-ad-object-history) | Qui a modifié cet objet AD, et quoi ? | Objet AD | Security DC 5136 |
| [P-HOST-TIMELINE](#p-host-timeline) | Que s'est-il passé sur l'hôte autour de l'alerte ? | Hôte, heure | Toutes |
| [P-LINUX-EXEC](#p-linux-exec) | Quelles commandes ont été lancées sur ce serveur Linux ? | Hôte | Kunai |
| [P-NET-IDS](#p-net-ids) | Le réseau a-t-il levé des alertes sur cette IP ? | IP | Suricata |

Les pivots P-PROC-TREE, P-USER-LOGONS et P-SRC-IP-SCOPE sont les plus référencés par les règles. Ce sont donc les candidats prioritaires à l'automatisation dans n8n : ils ne prennent en entrée que des champs déjà présents dans l'alerte.

## Requêtes

### P-PROC-TREE

```
index=main EventCode=1 host="<HOST>" (ProcessGuid="<GUID>" OR ParentProcessGuid="<GUID>")
| table _time host User ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort _time
```

### P-LOGON-SESSION

Méthode validée sur la règle WMIExec : `Logon_ID` est multivalué, et le Target Logon ID correspond à sa dernière valeur.

```
index=main host="<HOST>" EventCode=4624
| eval TargetLogonId=mvindex(Logon_ID, -1)
| search TargetLogonId="<LOGONID>"
| table _time host Account_Name Logon_Type Source_Network_Address TargetLogonId
```

### P-USER-LOGONS

```
index=main EventCode IN (4624, 4625, 4648) Account_Name="<USER>"
| stats count min(_time) as premier max(_time) as dernier values(Logon_Type) as types values(Source_Network_Address) as sources by host EventCode
| convert ctime(premier) ctime(dernier)
```

### P-LOGON-SUCCESS

```
index=main EventCode=4624 Source_Network_Address="<IP>"
| stats count min(_time) as premier values(Account_Name) as comptes by host Logon_Type
| convert ctime(premier)
```

### P-ACCOUNT-ACTIVITY

```
index=main (Account_Name="<USER>" OR User="*\\<USER>")
| stats count min(_time) as premier max(_time) as dernier values(EventCode) as evenements by host sourcetype
| convert ctime(premier) ctime(dernier)
```

### P-PRIV-USE

```
index=main EventCode IN (4672, 4673, 4674) Account_Name="<USER>"
| stats count values(Privileges) as privileges by host EventCode
```

### P-SRC-IP-SCOPE

```
index=main "<IP>"
| stats count min(_time) as premier max(_time) as dernier values(EventCode) as evenements by host sourcetype
| convert ctime(premier) ctime(dernier)
```

### P-NET-CONN

```
index=main EventCode=3 host="<HOST>"
| stats count min(_time) as premier max(_time) as dernier by Image DestinationIp DestinationPort
| sort - count
```

### P-DNS

```
index=main EventCode=22 host="<HOST>"
| stats count by Image QueryName
| sort - count
```

### P-PERSISTENCE

```
index=main host="<HOST>" (EventCode IN (4698, 4697, 7045) OR (EventCode=13 TargetObject="*\\CurrentVersion\\Run*"))
| table _time host EventCode User TargetObject Details
| sort _time
```

### P-HASH-SCOPE

```
index=main EventCode=1 Hashes="*<SHA256>*"
| stats count min(_time) as premier values(host) as hotes values(Image) as chemins values(User) as comptes
```

### P-KERBEROS-TGS

```
index=main EventCode=4769 Account_Name="<USER>*"
| stats count values(Service_Name) as services values(Ticket_Encryption_Type) as chiffrement by Client_Address
```

### P-PKINIT-AUTH

```
index=main EventCode=4768 Account_Name="<USER>"
| stats count min(_time) as premier values(Pre_Authentication_Type) as preauth values(Certificate_Issuer_Name) as emetteur by Client_Address
| convert ctime(premier)
```

### P-DC-REPLICATION

Les GUID correspondent aux droits DS-Replication-Get-Changes, DS-Replication-Get-Changes-All et DS-Replication-Get-Changes-In-Filtered-Set.

```
index=main EventCode=4662 ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" OR "89e95b76-444d-4c62-991a-0facbeda640c")
| stats count min(_time) as premier by Account_Name host
| convert ctime(premier)
```

### P-AD-OBJECT-HISTORY

```
index=main EventCode=5136 "<OBJET>"
| table _time host SubjectUserName ObjectDN AttributeLDAPDisplayName AttributeValue OperationType
| sort _time
```

### P-HOST-TIMELINE

```
index=main host="<HOST>" earliest="<HEURE-1h>" latest="<HEURE+1h>"
| table _time EventCode sourcetype User Image CommandLine TargetObject DestinationIp
| sort _time
```

### P-LINUX-EXEC et P-NET-IDS

Ces deux pivots dépendent des sourcetypes Kunai et Suricata de production, absents du lab. Leurs requêtes seront écrites et validées au démarrage du RUN.
