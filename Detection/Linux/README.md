# Détection — Linux

Source principale : Kunai (eBPF) sur LINSERV-DEV et LINSERV-BAST.

Règles attendues :

- Multiples commandes d'énumération (obligatoire)
- Activité de password looting (obligatoire)
- Accès à /etc/shadow (supplémentaires)

| ID | Règle | ATT&CK | Sévérité | Auteur | Statut | YAML | Fiche réflexe | Preuve de test |
|---|---|---|---|---|---|---|---|---|
| DM-LIN-001 | Commande d'enumeration locale  | T1082 | LOW | Killian Munt-Burion| En cours  | [linux_enumeration.yaml](linux_enumeration.yaml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-001.md) | [CSV](../../Tests/validation_environnement/DM-LIN-001.csv) |
| DM-LIN-002 | Recherche de secrets et mots de passe | T1552 | HIGH | Killian Munt-Buron | Finie | [linux_password_looting.yaml](linux_password_looting.yaml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-002.md) | [CSV](../../Tests/validation_environnement/DM-LIN-002.csv) |
| DM-LIN-003 |Acces a /etc/shadow | T1003 | HIGH | Killian Munt-Buron | Finie | [linux_acces_etc_shadow.yaml](linux_acces_etc_shadow.yaml) | [fiche](../../Investigation/fiches_reflexes/DM-LIN-003.md) | [CSV](../../Tests/validation_environnement/DM-LIN-003.csv) |


