# Fiche réflexe DM-AD-006 — Ajout à un groupe AD critique

| Champ | Valeur |
|---|---|
| Règle | DM-AD-006 — `[BUILD] [HIGH] Ajout d'un membre a un groupe AD critique` |
| MITRE | T1098 — Account Manipulation (Privilege Escalation / Persistence) |
| Sévérité | HIGH par défaut, **CRITICAL** si le groupe est de tier 0 |
| SLA qualification | HIGH/CRITICAL : notification immédiate |
| Source | `WinEventLog:Security` 4728 / 4732 / 4756 sur le DC |
| Règle liée | DM-AD-003 (Shadow Credentials — pour évaluer si le compte ajouté a été compromis via cette voie) |
| Auteur | Groupe 2 — Tim LEVADOUX |

## 1. Ce que l'alerte signifie

Un compte a été ajouté à un groupe de sécurité considéré comme critique (liste maintenue dans le lookup `critical_ad_groups.csv`). Les groupes de **tier 0** (Domain Admins, Enterprise Admins, Schema Admins, Administrators intégrés) donnent un contrôle total du domaine ou de la forêt. Les groupes de **tier 1** (Account Operators, Backup Operators, Server Operators, DnsAdmins, Group Policy Creator Owners) donnent des privilèges opérationnels qui permettent souvent une élévation indirecte vers tier 0.

## 2. Champs clés de l'alerte

- `TargetUserName` : groupe qui a reçu le nouveau membre
- `MemberName` / `MemberSid` : compte ajouté
- `SubjectUserName` : compte qui a fait l'ajout
- `tier` : 0 (contrôle total) ou 1 (privilèges opérationnels) — détermine `severity_hint`
- `ComputerName` : DC qui a traité la modification

## 3. Qualification (à faire en premier)

1. **Ce changement correspond-il à un ticket de changement planifié ?** Vérifier dans l'outil de ticketing de l'équipe infra avant toute action. Un changement approuvé en cours doit être documenté comme tel, pas retiré à tort.
2. **`SubjectUserName` est-il un administrateur connu ?** Comparer à la liste des comptes habilités à gérer ce groupe.
3. **Le compte ajouté (`MemberName`) est-il cohérent ?** Un compte de service, un compte récemment créé, ou un compte qui n'a historiquement jamais eu ce niveau de privilège est un signal fort.
4. **L'horaire est-il cohérent ?** Un ajout à Domain Admins à 3h du matin un dimanche, hors fenêtre de changement, est très suspect.
5. **Le compte acteur a-t-il été recemment visé par une autre alerte ?** Vérifier en particulier DM-AD-003 (Shadow Credentials) : un acteur qui a implanté une clé sur un compte puis l'utilise pour s'ajouter à un groupe critique est un scénario de compromission complet.

```spl
index=main source="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756) TargetUserName="<groupe>" earliest=-30d
| table _time SubjectUserName MemberName TargetUserName
| sort _time
```

## 4. Investigation — pivots

### P-USER-LOGONS — activité de l'acteur et du compte ajouté

```spl
index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769) ("<SubjectUserName>" OR "<MemberName>") earliest=-24h
| table _time ComputerName EventCode Account_Name Logon_Type Source_Network_Address
| sort _time
```

À chercher : connexion de l'acteur depuis un poste inhabituel juste avant l'ajout ; connexion du compte ajouté juste après, utilisant ses nouveaux privilèges.

### P-SRC-IP-SCOPE — périmètre de la machine source

```spl
index=* ("<src_ip>" OR "::ffff:<src_ip>") earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, EventCode, host
| convert ctime(first) ctime(last)
```

### P-PROC-TREE — processus à l'origine (si la source est un poste Windows du parc)

```spl
index=main host="<poste_source>" ((source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (source="WinEventLog:Security" EventCode=4688)) earliest=-1h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : `net.exe group /add`, `Add-ADGroupMember`, `dsa.msc` lancé par un compte inhabituel, outils d'administration AD tiers.

### P-PRIV-USE — usage des privilèges nouvellement acquis (pivot spécifique)

```spl
index=main source="WinEventLog:Security" EventCode=4672 Account_Name="<MemberName>" earliest=-24h
| table _time ComputerName Account_Name Privilege_List
| sort _time
```

À chercher : un 4672 (privilèges spéciaux attribués à l'ouverture de session) sur le compte ajouté, juste après l'ajout au groupe — preuve que les nouveaux droits ont déjà été exercés.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Ticket de changement approuvé, acteur connu | Faux positif (légitime) | Ajouter au lookup `dm_ad_006_exclusions.csv`, clôturer |
| Acteur inconnu ou hors horaires, groupe tier 1 | Vrai positif | Confinement (section 6), notification client |
| Groupe tier 0 (Domain Admins, Enterprise Admins, Schema Admins) | Vrai positif CRITIQUE | Confinement immédiat, escalade, investigation complète |
| Lié à une alerte DM-AD-003 récente sur le même compte | Vrai positif CRITIQUE, compromission confirmée | Confinement immédiat, traiter comme compromission du domaine |

## 6. Réponse

**Confinement**
- Retirer immédiatement le membre ajouté du groupe si l'ajout n'est pas confirmé légitime.
- Désactiver le compte ajouté (ou le compte acteur si compromis) le temps de l'investigation.
- Forcer une réauthentification / révocation des tickets Kerberos du compte ajouté (réinitialisation du mot de passe deux fois ; réinitialiser le mot de passe `krbtgt` deux fois si Domain Admins ou Enterprise Admins est concerné).

**Remédiation**
- Revoir qui dispose du droit de modifier l'appartenance de ces groupes (délégation ACL).
- Mettre en place un processus d'approbation (PAM / Just-In-Time) pour toute élévation vers un groupe de tier 0.
- Auditer régulièrement la composition réelle des groupes critiques face à l'inventaire attendu.

**À ne pas faire**
- Ne pas retirer le membre avant d'avoir confirmé qu'il ne s'agit pas d'un changement planifié en cours.
- Ne pas se limiter au retrait du groupe si le compte acteur est lui-même compromis : traiter l'incident à la source.

## 7. Notification

- HIGH (tier 1) ou CRITICAL (tier 0) : notification client immédiate dans les deux cas.

## 8. Éléments à consigner dans DFIR-IRIS

- `SubjectUserName`, `TargetUserName` (groupe), `MemberName`/`MemberSid`, `tier`, `ComputerName`, horodatage
- Confirmation ou non d'un ticket de changement associé
- Résultat du pivot P-PRIV-USE (usage confirmé ou non des nouveaux privilèges)
- Lien éventuel avec une alerte DM-AD-003 sur le même compte
- Verdict, justification et actions réalisées (heure, opérateur), y compris le retrait du groupe et la réinitialisation des mots de passe/krbtgt le cas échéant