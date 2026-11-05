# Matrice de priorisation et de triage

Les alertes de la file sont traitées par sévérité décroissante, puis par échéance SLA la plus proche. Une alerte HIGH ou CRITICAL doit être notifiée au client sous 2h et qualifiée sous 4h.

## Engagements de service (SLA)

| Sévérité | Notification client | Qualification | Investigations complémentaires |
|---|---|---|---|
| CRITICAL | 2h | 4h (rapport d'investigation v1) | 72h (rapport final) |
| HIGH | 2h | 4h (rapport d'investigation v1) | 72h (rapport final) |
| MEDIUM | Non requise | 8h | Non requises |
| LOW | Non requise | 12h | Non requises |

Les SLA courent à partir de l'heure de l'alerte, pas de la prise en charge. Le texte des engagements du sujet annonce une notification sous 4h et une qualification sous 8h, alors que le tableau du sujet donne 2h et 4h. Nous appliquons le tableau, qui est le plus exigeant. Ce point reste à confirmer avec les intervenants.

## Définition des niveaux

| Sévérité | Critère |
|---|---|
| CRITICAL | Compromission probable d'un actif Tier 0 ou des secrets du domaine, ou impact en cours |
| HIGH | Exécution, persistance privilégiée ou mouvement latéral d'un attaquant probable, sans atteinte confirmée au Tier 0 |
| MEDIUM | Technique d'attaque plausible mais souvent légitime, à qualifier |
| LOW | Signal faible ou reconnaissance sans suite |

## Sévérité par défaut de chaque règle

| Sévérité | Règles |
|---|---|
| CRITICAL | DM-AD-005 DCSync · DM-AD-007 Extraction de NTDS.dit · DM-WIN-004 Dump LSASS |
| HIGH | DM-AD-003 Shadow Credentials · DM-AD-006 Ajout à un groupe critique · DM-AD-008 Délégation Kerberos · DM-WIN-002 Service suspect · DM-WIN-005 Impacket WMIExec · DM-WIN-007 Effacement des journaux · DM-WIN-008 Modification de la politique d'audit |
| MEDIUM | DM-AD-001 Kerberoasting · DM-AD-002 AS-REP Roasting · DM-AD-004 Password spraying · DM-WIN-001 Tâche planifiée suspecte · DM-WIN-003 Clé Run · DM-WIN-006 Enfant inhabituel de WmiPrvSE · DM-WIN-009 LOLBin |
| LOW | Aucune règle à ce jour |

La sévérité de chaque règle est fixée par le champ `level` de son YAML et reprise dans le titre de l'alerte Splunk (`[BUILD] [HIGH] …`).

## Modificateurs de sévérité

| Situation | Effet |
|---|---|
| Actif Tier 0 touché (WINSERV-DC) ou compte AD-Admins / VIPs impliqué | +1 niveau |
| Plusieurs règles déclenchées sur le même hôte ou le même compte pendant la même fenêtre d'investigation | +1 niveau |
| Activité provenant d'une source extérieure aux plages connues (hors 192.168.10.0/24 et bastion) | +1 niveau |
| Activité correspondant à une exclusion documentée (outil d'administration connu, compte de service identifié) | −1 niveau ou clôture |

Les modificateurs propres à chaque règle se trouvent dans le champ `severity_modifiers` de son YAML.

## Issues possibles du triage

| Qualification | Critère | Action |
|---|---|---|
| Faux positif | La règle s'est déclenchée sur une activité qui ne correspond pas à la technique visée | Clôture dans IRIS, correction de la règle ([processus MCD](process_MCO_MCD.md)) |
| Vrai positif bénin | La technique est bien observée mais l'activité est légitime (administration planifiée, outil autorisé) | Clôture, exclusion documentée avec justification |
| Vrai positif malveillant | Activité adverse confirmée ou impossible à écarter | Ouverture d'un cas, [workflow d'investigation](../Investigation/README.md) complet |
| Indéterminé | Éléments insuffisants avant l'échéance de qualification | Traité comme malveillant, question posée au client |
