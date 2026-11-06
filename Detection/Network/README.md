# Détection — Réseau

Source principale : Suricata (eve.json) sur le pare-feu, Sysmon EventCode 3 et 22 sur les Windows.

Règles attendues :

- Scan de ports horizontal / vertical (obligatoire)
- Activité de beaconing C2 (obligatoire)
- DNS tunneling (supplémentaire)

| ID | Règle | ATT&CK | Sévérité | Auteur | Statut | YAML | Fiche réflexe | Preuve de test |
|---|---|---|---|---|---|---|---|---|
| DM-NET-001 | Scan de ports horizontal et vertical | T1046 | MEDIUM | Youssef MOUTALEB | test | [reseau_scan_ports.yml](reseau_scan_ports.yml) | [fiche](../../Investigation/fiches_reflexes/DM-NET-001.md) | [CSV](DM-NET-001_scan_ports_resultats.csv) |
| DM-NET-002 | Beaconing C2 - connexions regulieres vers l'exterieur | T1071 | HIGH | Youssef MOUTALEB | test | [reseau_beaconing_c2.yml](reseau_beaconing_c2.yml) | [fiche](../../Investigation/fiches_reflexes/DM-NET-002.md) | [CSV](DM-NET-002_beaconing_c2_resultats.csv) |
| DM-NET-003 | DNS tunneling - volume et longueur anormaux | T1048.003 | MEDIUM | Youssef MOUTALEB | test | [reseau_dns_tunneling.yml](reseau_dns_tunneling.yml) | [fiche](../../Investigation/fiches_reflexes/DM-NET-003.md) | [CSV](DM-NET-003_dns_tunneling_resultats.csv) |

Chaque règle est accompagnée de sa requête Splunk (`.spl`) et de sa liste d'exclusions (`DM-NET-00X_exclusions.csv`). Les trois règles ont été validées dans le lab (alertes reçues dans DFIR-IRIS) ; les fichiers `*_donnees_exemple_recalcule.csv` rejouent la détection sur le jeu d'exemple `test_log_suricata.json`.

Statuts : `draft` = rédigée, `test` = validée dans le lab (alerte reçue dans DFIR-IRIS ou collecte vérifiée).
