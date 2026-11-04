# DM-AD-008 – Modification d'une délégation Kerberos

| Champ | Valeur |
|---|---|
| ID | DM-AD-008 |
| Nom de l'alerte Splunk | [BUILD] [HIGH] Kerberos Delegation Modification |
| Sévérité | High |
| MITRE ATT&CK | T1134.005 – Access Token Manipulation (delegation) |
| Statut | Validée de bout en bout (Splunk vers DFIR-IRIS) |

## Description

Détecte la modification d'un attribut de délégation Kerberos sur un objet de l'annuaire. Une délégation mal configurée permet à un service d'usurper l'identité d'un utilisateur vers un autre service, voie classique d'élévation de privilèges. Lors des tests, la règle a détecté l'ajout de msDS-AllowedToDelegateTo sur l'objet SOC-TEST-DELEGATION par le compte Administrator.

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, */5 * * * * |
| Time Range | earliest=-15m, latest=now |
| Trigger | Number of Results > 0, Once |
| Action | Webhook vers http://soc_n8n:5678/webhook/alert |

## Pourquoi deux événements

- EventCode 5136 (Directory Service Changes) : modification directe de l'attribut msDS-AllowedToDelegateTo ou msDS-AllowedToActOnBehalfOfOtherIdentity (délégation contrainte et RBCD).
- EventCode 4738 (User Account Management) : modification d'un compte utilisateur portant une délégation.

Les rex extraient les champs du log brut (compte, objet, attribut, valeur) car ils ne sont pas toujours parsés automatiquement. Les eval harmonisent les deux types d'évènements vers les mêmes colonnes.

## Fiche réflexe

### Triage en 5 questions

1. Quel objet a été modifié, et quel attribut de délégation ?
2. Quel compte a fait la modification ? A-t-il le droit de poser une délégation ?
3. La modification correspond-elle à un changement d'infrastructure légitime connu ?
4. Vers quel service pointe la délégation (champ valeur) ? Un service sensible aggrave le risque.
5. L'objet nouvellement délégué a-t-il ensuite demandé des tickets (4769) ? Signe d'exploitation.

### Faux positifs fréquents

- Configuration légitime d'une délégation par les administrateurs lors d'un changement d'infrastructure.

### Actions

- Traiter en priorité (High).
- Annuler la délégation ajoutée et désactiver le compte modificateur s'il n'était pas autorisé.
- Revoir les droits d'écriture sur l'objet cible.
- Notification client sous 2h (SLA High).

## Test de validation (lab)

Ajout d'une délégation msDS-AllowedToDelegateTo sur SOC-TEST-DELEGATION depuis la Kali. Résultat : évènement 5136 détecté dans Splunk, alerte reçue dans DFIR-IRIS. Preuve : Tests/validation_environnement/DM-AD-008.csv et captures/DM-AD-008.png.

## Limites et écarts conception / implémentation

- La délégation non contrainte (via le flag userAccountControl) n'est pas couverte ici. C'est un choix de périmètre, à ajouter comme piste d'amélioration pour le RUN (via les évènements 4742/4738).
- La règle est filtrée sur host="DC.test.local" : à élargir si d'autres DC sont ajoutés au périmètre.
