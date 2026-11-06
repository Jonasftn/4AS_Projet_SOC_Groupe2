# Détection — Linux

Source principale : Kunai (eBPF) sur LINSERV-DEV et LINSERV-BAST.

Règles attendues :

- Multiples commandes d'énumération (obligatoire)
- Activité de password looting (obligatoire)
- Accès à /etc/shadow (supplémentaire)

| ID | Règle | ATT&CK | Sévérité | Auteur | Statut | YAML | Fiche réflexe | Preuve de test |
|---|---|---|---|---|---|---|---|---|
| DM-LIN-001 | Multiples commandes d'enumeration locale | T1082, T1033, T1016, T1049, T1069, T1087, T1018 | LOW | Killian MUNT-BURON | draft | [linux_enumeration.yml](linux_enumeration.yml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-001.md) | [CSV](../../Tests/validation_environnement/DM-LIN-001.csv) |
| DM-LIN-002 | Recherche de secrets et mots de passe | T1552 | HIGH | Killian MUNT-BURON | draft | [linux_password_looting.yml](linux_password_looting.yml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-002.md) | [CSV](../../Tests/validation_environnement/DM-LIN-002.csv) |
| DM-LIN-003 | Acces a /etc/shadow | T1003 | HIGH | Killian MUNT-BURON | draft | [linux_acces_etc_shadow.yml](linux_acces_etc_shadow.yml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-003.md) | [CSV](../../Tests/validation_environnement/DM-LIN-003.csv) |

Statuts : `draft` = rédigée, `test` = validée dans le lab (alerte reçue dans DFIR-IRIS ou collecte vérifiée).
