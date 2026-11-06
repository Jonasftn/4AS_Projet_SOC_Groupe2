# Détection — Active Directory

Règles de détection ciblant l'Active Directory, alimentées par le journal Security du contrôleur de domaine (politique d'audit DC).

| ID | Règle | ATT&CK | Sévérité | Auteur | Statut | YAML | Fiche réflexe | Preuve de test |
|---|---|---|---|---|---|---|---|---|
| DM-AD-001 | Kerberoasting - demande de tickets de service en RC4 | T1558.003 | MEDIUM | Tim LEVADOUX | test | [DM-AD-001.yml](DM-AD-001.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-001.md) | [CSV](../../Tests/validation_environnement/DM-AD-001.csv) |
| DM-AD-002 | AS-REP Roasting - AS-REQ sans pre-authentification | T1558.004 | MEDIUM | Tim LEVADOUX | test | [DM-AD-002.yml](DM-AD-002.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-002.md) | [CSV](../../Tests/validation_environnement/DM-AD-002.csv) |
| DM-AD-003 | Shadow Credentials - modification de msDS-KeyCredentialLink | T1556 | HIGH | Tim LEVADOUX | test | [DM-AD-003.yml](DM-AD-003.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-003.md) | [CSV](../../Tests/validation_environnement/DM-AD-003.csv) |
| DM-AD-004 | Password spraying | T1110.003 | MEDIUM | Amelie SAUVAN-MAGNET | test | [ad_password_spraying.yml](ad_password_spraying.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-004.md) | [CSV](../../Tests/validation_environnement/DM-AD-004.csv) |
| DM-AD-005 | DCSync - replication d'annuaire par un compte non DC | T1003.006 | CRITICAL | Amelie SAUVAN-MAGNET | test | [ad_dcsync.yml](ad_dcsync.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-005.md) | [CSV](../../Tests/validation_environnement/DM-AD-005.csv) |
| DM-AD-006 | Ajout d'un membre a un groupe AD critique | T1098 | HIGH | Tim LEVADOUX | test | [DM-AD-006.yml](DM-AD-006.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-006.md) | [CSV](../../Tests/validation_environnement/DM-AD-006.csv) |
| DM-AD-007 | Extraction de NTDS.dit | T1003.003 | CRITICAL | Nathan SACIER | test | [ad_ntds_dit_dump.yml](ad_ntds_dit_dump.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-007.md) | [CSV](../../Tests/validation_environnement/DM-AD-007.csv) |
| DM-AD-008 | Modification d'une delegation Kerberos | T1134.005 | HIGH | Amelie SAUVAN-MAGNET | test | [ad_delegation_kerberos.yml](ad_delegation_kerberos.yml) | [fiche](../../Investigation/fiches_reflexes/DM-AD-008.md) | [CSV](../../Tests/validation_environnement/DM-AD-008.csv) |

Chaque YAML suit le format pseudo-Sigma du groupe : logique de détection, sources requises, sévérité et modificateurs, faux positifs, exclusions, contournements connus, requête Splunk et paramètres de l'alerte, réponse (endiguement, remédiation), pivots d'investigation, tests.

Statuts : `draft` = rédigée, `test` = validée dans le lab (alerte reçue dans DFIR-IRIS ou collecte vérifiée).
