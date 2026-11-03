# Fiche réflexe DM-AD-002 — AS-REP Roasting (TGT sans pré-authentification)

| Champ | Valeur |
|---|---|
| Règle | DM-AD-002 — `[BUILD] [MEDIUM] AS-REP Roasting - AS-REQ sans pre-authentification` |
| MITRE | T1558.004 — Credential Access |
| Sévérité | MEDIUM (HIGH si `nb_comptes` ≥ 2 ou compte privilégié exposé) |
| SLA qualification | MEDIUM : 8 h — HIGH : selon SLA HIGH |
| Source | `WinEventLog:Security` 4768 sur le DC |
| Règle liée | DM-AD-004 (énumération de comptes, kerbrute) |
| Auteur | Groupe 2 — Tim LEVADOUX |

## 1. Ce que l'alerte signifie

Le DC a délivré un TGT sans pré-authentification pour un ou plusieurs comptes. Pour obtenir ce TGT, il suffit de connaître le nom du compte : aucun mot de passe n'est demandé. La réponse contient une partie chiffrée avec le hash du compte, qu'un attaquant peut casser hors ligne.

**Toute alerte révèle au minimum une mauvaise configuration** (compte avec `Do not require Kerberos preauthentication`). Même un faux positif doit donc déboucher sur une action corrective.

## 2. Champs clés de l'alerte

- `comptes` / `nb_comptes` : comptes pour lesquels un TGT a été délivré sans pré-auth
- `src_ip` : machine d'où vient la demande
- `enc_types` : chiffrement du ticket (`0x17` = RC4, cassage plus rapide ; `0x12` = AES256)
- `ComputerName` : DC qui a répondu
- `first_seen` / `last_seen` : fenêtre de l'activité

## 3. Qualification (à faire en premier)

1. **La source est-elle connue ?** Rechercher `src_ip` dans l'inventaire. Aucun identifiant n'est requis pour cette attaque, donc une IP hors parc ou non jointe au domaine (Kali, VPN) est un indicateur fort de vrai positif.
2. **Une énumération a-t-elle précédé la demande ?** Vérifier si DM-AD-004 s'est déclenchée sur la même `src_ip`. Un balayage de noms suivi d'un 4768 sans pré-auth correspond au schéma classique `kerbrute` puis `GetNPUsers`.
3. **Le compte est-il connu sans pré-auth ?** Lister les comptes concernés sur le DC :

   ```powershell
   Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, MemberOf, PasswordLastSet | Select Name, PasswordLastSet, MemberOf
   ```

   Un compte absent de l'inventaire ou dont l'attribut a été modifié récemment peut indiquer qu'un attaquant l'a désactivée lui-même. Dans ce cas, chercher un 4738 (modification de compte) sur ce compte.
4. **Le compte est-il privilégié ?** Membre d'un groupe d'administration → relever la sévérité.
5. **Comportement habituel ?** Ce couple compte/IP produit-il déjà ce type de 4768 les jours précédents ?

```spl
index=main source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0 earliest=-7d
| stats count values(Client_Address) as sources by Account_Name, Result_Code
```

## 4. Investigation — pivots

### P-USER-LOGONS — activité des comptes exposés

```spl
index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769 OR EventCode=4738) ("<compte_1>" OR "<compte_2>") earliest=-24h
| table _time ComputerName EventCode Account_Name Logon_Type Source_Network_Address Client_Address
| sort _time
```

À chercher : une connexion du compte exposé depuis une machine inhabituelle **après** l'alerte, signe d'un mot de passe cassé et réutilisé. Un 4738 qui a désactivé la pré-auth peu avant l'alerte est également suspect.

### P-SRC-IP-SCOPE — périmètre de la machine source

```spl
index=* ("<src_ip>" OR "::ffff:<src_ip>") earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, EventCode, host
| convert ctime(first) ctime(last)
```

À chercher : 4768 en échec (`Result_Code=0x6` principal inconnu, `0x18` mauvais mot de passe) en volume (énumération), autres alertes BUILD sur cette IP.

### P-PROC-TREE — processus à l'origine (uniquement si la source est un poste Windows du parc)

```spl
index=main host="<poste_source>" ((source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) OR (source="WinEventLog:Security" EventCode=4688)) earliest=-1h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : `Rubeus.exe asreproast`, PowerShell `Get-ASREPHash` / `Invoke-ASREPRoast`, binaires inconnus. Si la source n'est pas un poste du parc, ce pivot n'apporte rien : noter l'absence de télémétrie dans le case.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Compte inventorié sans pré-auth, source légitime connue (application) | Faux positif technique | Ajouter au lookup `dm_ad_002_exclusions.csv` **et** ouvrir une action corrective (pré-auth ou mot de passe fort) |
| Source inconnue ou hors parc | Vrai positif | Confinement (section 6), notification client |
| Énumération DM-AD-004 sur la même source | Vrai positif HIGH | Confinement immédiat, escalade |
| Compte exposé utilisé ailleurs ensuite | Vrai positif HIGH, compromission probable | Confinement immédiat, investigation de la session |

## 6. Réponse

**Confinement**
- Isoler la machine source (ou bloquer son accès au DC).
- Réinitialiser le mot de passe des comptes exposés : le hash est déjà sorti, activer la pré-auth ne suffit pas.
- Activer la pré-authentification sur les comptes concernés.

**Remédiation**
- Mot de passe long et aléatoire sur les comptes qui doivent rester sans pré-auth.
- Audit périodique de l'attribut `DONT_REQ_PREAUTH` (commande PowerShell en section 3).
- Forcer AES et désactiver RC4 sur le domaine.

**À ne pas faire**
- Ne pas ignorer l'alerte au motif que le compte est peu privilégié : c'est souvent la première marche d'une escalade.
- Ne pas se contenter de cocher la pré-auth sans changer le mot de passe.

## 7. Notification

- MEDIUM : pas de notification client, qualification sous 8 h.
- HIGH, vrai positif confirmé ou compte privilégié exposé : notifier le client.

## 8. Éléments à consigner dans DFIR-IRIS

- `src_ip`, `ComputerName`, liste des `comptes`, `enc_types`, `first_seen` / `last_seen`
- Résultat de l'inventaire des comptes sans pré-auth
- Lien éventuel avec une alerte DM-AD-004
- Résultats des pivots (captures ou exports des recherches)
- Verdict, justification et actions réalisées (heure, opérateur), y compris la date de réinitialisation des mots de passe