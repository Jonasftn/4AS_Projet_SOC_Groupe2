# Détection — Windows

Règles de détection ciblant les postes et serveurs Windows, alimentées par Sysmon (config sysmon-modular) et les journaux Security/System.

| ID | Règle | ATT&CK | Sévérité | Auteur | Statut | YAML | Fiche réflexe | Preuve de test |
|---|---|---|---|---|---|---|---|---|
| DM-WIN-001 | Creation d'une tache planifiee suspecte | T1053.005 | MEDIUM | Jonas FONTAINE-DEMAY | test | [tache_planifiee_suspecte.yml](tache_planifiee_suspecte.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-001.md) | [CSV](../../Tests/validation_environnement/DM-WIN-001.csv) |
| DM-WIN-002 | Creation d'un service suspect | T1543.003 | HIGH | Jonas FONTAINE-DEMAY | test | [service_suspect.yml](service_suspect.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-002.md) | [CSV](../../Tests/validation_environnement/DM-WIN-002.csv) |
| DM-WIN-003 | Creation ou modification d'une cle Run | T1547.001 | MEDIUM | Jonas FONTAINE-DEMAY | test | [creation_modification_cle_run.yml](creation_modification_cle_run.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-003.md) | [CSV](../../Tests/validation_environnement/DM-WIN-003.csv) |
| DM-WIN-004 | Dump de la memoire LSASS | T1003.001 | CRITICAL | Nathan SACIER | test | [windows_dump_lsass.yml](windows_dump_lsass.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-004.md) | [CSV](../../Tests/validation_environnement/DM-WIN-004.csv) |
| DM-WIN-005 | Impacket WMIExec - execution de commandes a distance | T1047 | HIGH | Nathan SACIER | test | [windows_impacket_wmiexec.yml](windows_impacket_wmiexec.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-005.md) | [CSV](../../Tests/validation_environnement/DM-WIN-005.csv) |
| DM-WIN-006 | Processus enfant inhabituel de WmiPrvSE (variante silentcommand) | T1047 | MEDIUM | Nathan SACIER | test | [windows_wmiexec_enfant_wmiprvse.yml](windows_wmiexec_enfant_wmiprvse.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-006.md) | [CSV](../../Tests/validation_environnement/DM-WIN-006.csv) |
| DM-WIN-007 | Effacement des journaux d'evenements | T1070.001 | HIGH | Amelie SAUVAN-MAGNET | test | [windows_effacement_journaux.yml](windows_effacement_journaux.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-007.md) | [CSV](../../Tests/validation_environnement/DM-WIN-007.csv) |
| DM-WIN-008 | Modification de la politique d'audit | T1562.002 | HIGH | Nathan SACIER | test | [windows_modification_politique_audit.yml](windows_modification_politique_audit.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-008.md) | [CSV](../../Tests/validation_environnement/DM-WIN-008.csv) |
| DM-WIN-009 | Utilisation de LOLBin pour telechargement ou execution | T1218 | MEDIUM | Jonas FONTAINE-DEMAY | test | [utilisation_lolbin.yml](utilisation_lolbin.yml) | [fiche](../../Investigation/fiches_reflexes/DM-WIN-009.md) | [CSV](../../Tests/validation_environnement/DM-WIN-009.csv) |

Chaque YAML suit le format pseudo-Sigma du groupe : logique de détection, sources requises, sévérité et modificateurs, faux positifs, exclusions, contournements connus, requête Splunk et paramètres de l'alerte, réponse (endiguement, remédiation), pivots d'investigation, tests.

Statuts : `draft` = rédigée, `test` = validée dans le lab (alerte reçue dans DFIR-IRIS ou collecte vérifiée).
