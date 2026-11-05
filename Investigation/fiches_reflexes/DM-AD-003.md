# Fiche réflexe DM-AD-003 — Shadow Credentials (msDS-KeyCredentialLink)

| Champ | Valeur |
|---|---|
| Règle | DM-AD-003 — `[BUILD] [HIGH] Shadow Credentials - modification de msDS-KeyCredentialLink` |
| MITRE | T1556 — Modify Authentication Process (Persistence / Credential Access) |
| Sévérité | HIGH dès le premier événement |
| SLA qualification | HIGH : notification immédiate |
| Source | `WinEventLog:Security` 5136 sur le DC |
| Règle liée | DM-AD-006 (ajout à un groupe critique — pour évaluer le niveau de privilège de la cible) |
| Auteur | Groupe 2 — Tim LEVADOUX |

## 1. Ce que l'alerte signifie

Un acteur a ajouté une valeur à l'attribut `msDS-KeyCredentialLink` d'un objet utilisateur ou ordinateur. Cet attribut sert normalement à Windows Hello for Business et à l'inscription hybride Azure AD. Y ajouter une clé publique permet de s'authentifier **sans connaître le mot de passe** de la cible (PKINIT), puis, via S4U2Self, de récupérer son hash NT. Aucune réinitialisation de mot de passe n'est nécessaire côté attaquant : c'est une technique très discrète qui contourne entièrement l'authentification classique.

**Un seul événement suffit** : il n'y a pas de seuil de volume comme pour le Kerberoasting.

## 2. Champs clés de l'alerte

- `SubjectUserName` : compte qui a fait la modification (l'attaquant potentiel)
- `ObjectDN` : objet cible (DN complet, indique l'OU et le nom)
- `ObjectClass` : `user` ou `computer`
- `OperationType` : `%%14674` = valeur ajoutée
- `DSName` : DC qui a traité la modification

## 3. Qualification (à faire en premier)

1. **Le compte `SubjectUserName` a-t-il une légitimité à écrire sur cet objet ?** Vérifier s'il s'agit d'un administrateur AD connu, d'un outil PAM, ou d'un compte inattendu.
2. **`ObjectClass` est-il `computer` ?** C'est le cas le plus fréquent en environnement hybride (Azure AD Connect). Vérifier que le compte source correspond bien au compte de synchronisation attendu. S'il ne figure pas dans le lookup d'exclusions, c'est un signal fort.
3. **L'objet cible est-il privilégié ?** Un compte membre de Domain Admins, Enterprise Admins ou tout groupe critique (cf. DM-AD-006) doit faire monter la qualification en urgence absolue.
4. **Le compte source a-t-il normalement ce droit ?** Vérifier l'ACL de l'objet cible :

   ```powershell
   dsacls "<ObjectDN>" | Select-String "KeyCredentialLink"
   Get-ADObject -Identity "<ObjectDN>" | Get-Acl
   ```

   Si le compte source n'apparaît dans aucune délégation documentée, c'est très probablement une exploitation d'une ACL mal configurée (GenericWrite, GenericAll, WriteProperty).
5. **Un deuxième événement a-t-il suivi ?** Une suppression (`OperationType=%%14675`) juste après l'ajout peut indiquer que l'attaquant tente de nettoyer ses traces après authentification.

```spl
index=main source="WinEventLog:Security" EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink" ObjectDN="*<objet_cible>*" earliest=-24h
| table _time OperationType SubjectUserName ObjectDN
| sort _time
```

## 4. Investigation — pivots

### P-USER-LOGONS — activité du compte source et du compte cible

```spl
index=main source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769) ("<SubjectUserName>" OR "<nom_objet_cible>") earliest=-24h
| table _time ComputerName EventCode Account_Name Logon_Type Source_Network_Address
| sort _time
```

À chercher : le compte source authentifié depuis un poste inhabituel juste avant la modification.

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

À chercher : `Whisker.exe`, `pywhisker`, `Rubeus.exe` (notamment `/getnthash`), scripts PowerShell manipulant `msDS-KeyCredentialLink`.

### P-PKINIT-AUTH — authentification PKINIT suspecte sur le compte cible (pivot spécifique)

```spl
index=main source="WinEventLog:Security" EventCode=4768 Account_Name="<nom_objet_cible>" earliest=-24h
| table _time ComputerName Account_Name Pre_Authentication_Type Client_Address Certificate_Issuer_Name
| sort _time
```

À chercher : un 4768 avec un type de pré-authentification par certificat (PKINIT, `Pre_Authentication_Type=16` ou champ `Certificate_Issuer_Name` renseigné), survenant peu après l'ajout de la clé — c'est la preuve que la clé a été utilisée pour s'authentifier.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Compte de sync AAD connu, objet `computer`, absent par erreur du lookup | Faux positif | Ajouter au lookup `dm_ad_003_exclusions.csv`, clôturer |
| Compte source sans délégation documentée sur l'objet | Vrai positif | Confinement immédiat (section 6), notification client |
| Objet cible privilégié (Domain/Enterprise Admins) | Vrai positif CRITIQUE | Confinement immédiat, escalade, investigation complète de la session de l'attaquant |
| 4768 PKINIT confirmé sur le compte cible après l'ajout | Vrai positif confirmé, compromission active | Confinement immédiat, considérer le compte cible comme compromis |

## 6. Réponse

**Confinement**
- Supprimer immédiatement la valeur ajoutée sur `msDS-KeyCredentialLink` de l'objet cible (`Whisker.exe remove`, `pywhisker --action remove`, ou ADSI Edit).
- Réinitialiser le mot de passe du compte cible par précaution, au cas où le hash NT aurait déjà été récupéré via S4U2Self.
- Isoler le poste source et désactiver le compte attaquant si la modification n'est pas légitime.

**Remédiation**
- Revoir les délégations ACL (GenericWrite, GenericAll, WriteProperty) sur les objets utilisateur et ordinateur, idéalement avec BloodHound pour cartographier les chemins d'attaque.
- Restreindre les groupes ayant un droit d'écriture sur `msDS-KeyCredentialLink` au strict nécessaire.
- Vérifier l'absence d'autres clés résiduelles sur les comptes à privilèges.

**À ne pas faire**
- Ne pas se contenter de réinitialiser le mot de passe sans supprimer la clé : elle permet toujours l'authentification PKINIT indépendamment du mot de passe.
- Ne pas clôturer le case sans avoir identifié l'origine du droit d'écriture.

## 7. Notification

- HIGH dès le premier événement : notification client immédiate.
- CRITIQUE si l'objet cible est privilégié ou si l'authentification PKINIT est confirmée.

## 8. Éléments à consigner dans DFIR-IRIS

- `SubjectUserName`, `ObjectDN`, `ObjectClass`, `DSName`, horodatage de la modification
- Résultat de la vérification de l'ACL de l'objet cible
- Résultat du pivot P-PKINIT-AUTH (authentification confirmée ou non)
- Verdict, justification et actions réalisées (heure, opérateur), y compris la suppression de la clé et la réinitialisation du mot de passe