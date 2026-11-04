# DM-WIN-007 – Effacement des journaux d'évènements

| Champ | Valeur |
|---|---|
| ID | DM-WIN-007 |
| Nom de l'alerte Splunk | [BUILD] [HIGH] Effacement des journaux d'evenements |
| Sévérité | High |
| MITRE ATT&CK | T1070.001 – Clear Windows Event Logs |
| Statut | Validée de bout en bout (Splunk → DFIR-IRIS) |

## Description

Détecte l'effacement d'un journal Windows ou l'exécution d'une commande d'effacement. Lors des tests, la règle a détecté l'effacement du journal System sur le contrôleur de domaine via wevtutil cl System exécuté à distance (smbexec), avec remontée de l'évènement 104 et de la ligne de commande vue par Sysmon.

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, */5 * * * * |
| Time Range | earliest=-15m, latest=now |
| Trigger | Number of Results > 0, Once |
| Action | Webhook vers http://soc_n8n:5678/webhook/alert |

## Pourquoi trois sources

- EventCode 1102 (journal Security) : généré quand le journal Security est vidé.
- EventCode 104 (journal System) : généré quand un journal est vidé via l'Observateur d'évènements.
- Sysmon EventCode 1 : capture la ligne de commande (wevtutil cl, Clear-EventLog).

Le motif wevtutil cl isolé entre espaces évite le bruit de Windows Defender qui lance régulièrement wevtutil install-manifest.

## Fiche réflexe

### Triage en 5 questions

1. Quel journal a été vidé (Security via 1102, System via 104) ?
2. Sur quelle machine ? Un DC ou un bastion fait monter la sévérité.
3. Quel compte est à l'origine de l'effacement ?
4. Une maintenance planifiée était-elle prévue à cette heure ? À confirmer avec le client.
5. Que s'est-il passé sur la machine juste avant l'effacement ? Les évènements déjà remontés dans Splunk restent disponibles.

### Faux positifs fréquents

- Opération de maintenance planifiée par un administrateur.
- Bruit de Windows Defender (wevtutil install-manifest), écarté par le motif.

### Actions

- Traiter en priorité (High), surtout sur un DC.
- S'appuyer sur la copie centralisée des journaux dans Splunk.
- Retrouver comment le compte utilisé a obtenu ses droits.
- Notification client sous 2h (SLA High).

## Test de validation (lab)

Exécution de wevtutil cl System depuis la Kali vers le DC (smbexec). Résultat : évènement 104 détecté dans Splunk, alerte reçue dans DFIR-IRIS. Preuve : Tests/validation_environnement/DM-WIN-007.csv et captures/DM-WIN-007.png.

## Limites et écarts conception / implémentation

- Un attaquant qui arrête le service Event Log avant d'agir peut contourner la détection.
- L'effacement par API sans passer par wevtutil n'est pas couvert par le volet Sysmon, mais reste détecté par les évènements natifs 1102/104.
