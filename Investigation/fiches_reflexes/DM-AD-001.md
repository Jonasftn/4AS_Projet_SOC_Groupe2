# Fiche réflexe DM-AD-001 — Kerberoasting (tickets de service RC4)

| Champ | Valeur |
|---|---|
| Règle | DM-AD-001 — `[BUILD] [MEDIUM] Kerberoasting - demande de tickets de service en RC4` |
| MITRE | T1558.003 — Credential Access |
| Sévérité | MEDIUM (HIGH si `nb_spn` ≥ 3 ou compte de service privilégié ciblé) |
| SLA qualification | MEDIUM : 8 h — HIGH : selon SLA HIGH |
| Source | `WinEventLog:Security` 4769 sur le DC |
| Auteur | Groupe 2 — Tim LEVADOUX |

## 1. Ce que l'alerte signifie

Un compte du domaine a obtenu un ou plusieurs tickets de service Kerberos chiffrés en RC4 pour des SPN portés par des comptes utilisateurs. Un attaquant peut casser ces tickets hors ligne pour récupérer le mot de passe du compte de service. Aucun impact immédiat, mais c'est souvent l'étape qui précède une élévation de privilèges.

## 2. Champs clés de l'alerte

- `account` : compte qui a demandé les tickets
- `src_ip` : machine d'où vient la demande
- `spn` / `nb_spn` : services ciblés et leur nombre
- `ComputerName` : DC qui a délivré les tickets
- `first_seen` / `last_seen` : fenêtre de l'activité

## 3. Qualification (à faire en premier)

1. **La source est-elle connue ?** Rechercher `src_ip` dans l'inventaire et le lookup d'exclusions. Une IP hors parc ou non jointe au domaine (ex. poste Linux, Kali) est un indicateur fort de vrai positif.
2. **Le compte demandeur a-t-il une raison légitime ?** Compte de supervision, d'inventaire ou application ancienne exigeant RC4 → faux positif probable, à documenter.
3. **Combien de SPN ?** Plusieurs SPN différents en quelques minutes = énumération typique (Rubeus, impacket `GetUserSPNs`, `Invoke-Kerberoast`).
4. **Quels comptes de service sont ciblés ?** Vérifier si l'un d'eux est membre d'un groupe privilégié → relever la sévérité.
5. **Comportement habituel ?** Le compte a-t-il déjà demandé ces SPN en RC4 les jours précédents ?

```spl
index=main source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17 Account_Name="<account>*" earliest=-7d
| stats count dc(Service_Name) as nb_spn values(Service_Name) as spn by date_mday, Client_Address
```

## 4. Investigation — pivots

### P-USER-LOGONS — activité du compte demandeur

```spl
index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769) "<account>" earliest=-24h
| table _time ComputerName EventCode Account_Name Logon_Type Source_Network_Address Client_Address Service_Name
| sort _time
```

À chercher : connexion depuis une machine inhabituelle, horaires anormaux, 4768 (TGT) depuis la même `src_ip` juste avant.

### P-SRC-IP-SCOPE — périmètre de la machine source

```spl
index=* ("<src_ip>" OR "::ffff:<src_ip>") earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, EventCode, host
| convert ctime(first) ctime(last)
```

À chercher : autres comptes utilisés depuis cette IP, requêtes LDAP massives, autres alertes BUILD sur la même source.

### P-PROC-TREE — processus à l'origine de la demande (si la source est un poste Windows du parc)

```spl
index=main host="<poste_source>" ((source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (source="WinEventLog:Security" EventCode=4688)) earliest=-1h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : `Rubeus.exe`, `powershell` avec `Invoke-Kerberoast` / `KerberosRequestorSecurityToken`, `setspn -Q`, binaires inconnus dans `%TEMP%` ou `Downloads`.

### Suivi — utilisation d'un mot de passe cassé

```spl
index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4768) ("<svc_account_1>" OR "<svc_account_2>") earliest=-24h
| table _time ComputerName EventCode Account_Name Logon_Type Source_Network_Address
```

Une connexion interactive ou réseau d'un compte de service depuis une machine qui n'est pas son serveur applicatif = mot de passe probablement compromis → passer en HIGH.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Source et compte légitimes, comportement habituel | Faux positif | Ajouter au lookup `dm_ad_001_exclusions.csv` avec justification, clôturer |
| Source inconnue ou outil offensif identifié | Vrai positif | Confinement (section 6), notification client |
| Compte de service ciblé utilisé ailleurs ensuite | Vrai positif HIGH | Confinement immédiat, escalade |
| Doute (pas de télémétrie sur la source) | À confirmer | Contacter le propriétaire du poste / du compte, conserver le case ouvert |

## 6. Réponse

**Confinement**
- Isoler le poste source du réseau (ou bloquer son accès au DC).
- Désactiver temporairement le compte demandeur si la demande n'est pas légitime.
- Réinitialiser le mot de passe des comptes de service ciblés (deux fois s'ils sont privilégiés).

**Remédiation**
- Mots de passe longs (25+ caractères) et aléatoires, ou migration vers des gMSA.
- Forcer AES (`msDS-SupportedEncryptionTypes`) et désactiver RC4 sur le domaine.
- Retirer les SPN inutiles et les droits privilégiés des comptes de service.

**À ne pas faire**
- Ne pas réinitialiser le compte avant d'avoir identifié la machine source (l'attaquant serait prévenu et on perdrait la piste).
- Ne pas supprimer de SPN en production sans valider avec le propriétaire applicatif.

## 7. Notification

- MEDIUM : pas de notification client, qualification sous 8 h.
- HIGH, vrai positif confirmé ou compte de service privilégié ciblé : notifier le client.

## 8. Éléments à consigner dans DFIR-IRIS

- `account`, `src_ip`, `ComputerName`, liste des `spn`, `first_seen` / `last_seen`
- Résultats des pivots (captures ou exports des recherches)
- Verdict, justification et actions réalisées (heure, opérateur)
- Si faux positif : entrée ajoutée au lookup d'exclusions