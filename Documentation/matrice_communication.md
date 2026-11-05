# Matrice de communication

Toute communication écrite avec le client passe par la conversation Teams dédiée aux sollicitations client du groupe et respecte la nomenclature imposée. Le téléphone est réservé aux urgences, et chaque appel est suivi d'un écrit.

## Nomenclature

- `[5A-4AS] [Groupe-2] Incident n°X - notification client`
- `[5A-4AS] [Groupe-2] Incident n°X - rapport d'investigation_v1`
- `[5A-4AS] [Groupe-2] Incident n°X - rapport d'investigation_final`

## Matrice

| Situation | Émetteur | Destinataire | Canal | Délai | Message |
|---|---|---|---|---|---|
| Alerte qualifiée faux positif ou bénigne | Analyste | Équipe SOC | Note dans IRIS | À la clôture | Aucun message client |
| Question au client pour qualifier (activité légitime ou non ?) | Analyste | Client | Teams | Dès le besoin, avant l'échéance de qualification | notification client |
| Incident HIGH ou CRITICAL détecté | Référent communication | Client | Teams | 2h après l'alerte | notification client |
| Attaque en cours, action urgente du client (isolement, reset de compte) | Référent communication | Client | Téléphone, puis Teams | Immédiat | Compte rendu écrit de l'appel, envoyé comme notification client |
| Qualification HIGH ou CRITICAL | Rédacteur des rapports | Client | Teams | 4h après l'alerte | rapport d'investigation_v1 |
| Changement de sévérité ou découverte majeure (nouvel hôte, compte admin compromis) | Référent communication | Client | Teams, et téléphone si CRITICAL | Dès la découverte | Nouvelle notification client |
| Investigations complémentaires terminées | Rédacteur des rapports | Client | Teams | 72h après l'alerte | rapport d'investigation_final |
| Escalade interne (doute de qualification, incident CRITICAL) | Analyste | Responsable SOC | Oral ou canal interne | Immédiat | Point de situation |
| Panne de collecte ou de la chaîne d'alerte | Responsable outillage | Équipe SOC, puis client si la perte de visibilité dépasse le délai de qualification | Canal interne, puis Teams | Dès la détection | Périmètre aveugle et durée |

Les contacts côté Dunder Mifflin (interlocuteur sécurité, DSI, numéro d'astreinte) sont à confirmer en RUN.

## Contenu minimal d'une notification client

1. **Contexte** : ce qui a été détecté, sur quel actif, à quelle heure.
2. **Qualification provisoire** et niveau d'urgence.
3. **Ce que l'on sait et ce que l'on ne sait pas encore**, avec les inconnues prioritaires.
4. **Actions recommandées** au client, et ce qu'il ne faut pas faire (éteindre une machine, alerter l'attaquant).
5. **Prochaine communication** prévue et son échéance.

## Trame d'appel client

1. Se présenter comme analyste SOC d'AEGIS CyberProtect et annoncer l'objet de l'appel.
2. Donner le contexte sans jargon : serveur touché, date et heure, ce que fait l'attaquant.
3. Faire le point : avancement de l'investigation, stade de l'attaque, inconnues.
4. Recommander les mesures d'endiguement et rappeler ce qu'il ne faut pas faire.
5. Convenir de la suite : décision du client, prochaine notification, cellule de crise si nécessaire.
