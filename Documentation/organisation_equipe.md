# Organisation de l'équipe

Pendant le BUILD, l'équipe se répartit par domaine de détection. Pendant le RUN, elle se répartit par rôle dans le traitement d'incident, pour que chaque SLA ait un responsable nommé.

## Rôles pendant le BUILD

| Membre | Règles | Autres responsabilités |
|---|---|---|
| Tim LEVADOUX | DM-AD-001, 002, 003, 006 | Revue des faux positifs AD |
| Amelie SAUVAN-MAGNET | DM-AD-004, 005, 008, DM-WIN-007 | Gestion des alertes Windows |
| Nathan SACIER | DM-AD-007, DM-WIN-004, 005, 006, 008 | Tests unitaires et validation |
| Jonas FONTAINE-DEMAY | DM-WIN-001, 002, 003, 009 | Documentation des processus |
| Killian / Youssef | Règles Linux (DM-LIN) et Réseau (DM-NET) | Intégration Kunai et Suricata |

## Rôles pendant le RUN

| Rôle | Responsabilité | SLA porté | Titulaire |
|---|---|---|---|
| Responsable SOC | Arbitre la qualification et la sévérité, valide tout envoi au client | Tous | Jonas Killian |
| Analyste triage (N1) | Surveille IRIS, prend en charge et qualifie les alertes | Qualification 4h, 8h, 12h | Youssef Amélie |
| Analyste investigation (N2) | Déroule les pivots et reconstitue la chaîne d'attaque | Rapport v1 4h | Tim Nathan |
| Référent communication | Rédige les notifications, mène l'appel client | Notification 2h | Amélie Youssef |
| Rédacteur des rapports | Consolide les rapports v1 et final | Rapport final 72h | Killian |
| Responsable outillage | MCO de la chaîne, correction des règles et des exclusions en RUN | Disponibilité de la détection | Nathan |

