# Processus MCO et MCD

Le MCO (maintien en condition opérationnelle) garantit que la chaîne collecte → Splunk → n8n → IRIS fonctionne. Le MCD (maintien en condition de détection) garantit que les règles détectent toujours ce qu'elles doivent détecter, sans noyer l'analyste. Une règle muette ne se voit pas : il faut donc vérifier les deux activement.

## Maintien en condition opérationnelle (MCO)

| Contrôle | Comment | Fréquence |
|---|---|---|
| Sources silencieuses | Recherche ci-dessous : tout couple hôte / sourcetype sans événement depuis plus d'une heure | Début de chaque vacation |
| Exécution des règles | Recherches planifiées sautées ou en erreur (Activity > Jobs, logs internes du scheduler) | Début de chaque vacation |
| Chaîne d'alerte de bout en bout | Envoyer une alerte de test au webhook n8n et vérifier qu'elle arrive dans IRIS | Après chaque modification de n8n ou d'IRIS |
| Forwarders Windows | Configuration du Splunk_TA_windows : `evt_resolve_ad_obj = false` sur le DC, sinon le journal Security ne remonte pas | À chaque nouvel hôte |
| Configuration versionnée | `savedsearches.conf`, workflows n8n et YAML des règles sont dans le Git ; aucune modification directe en prod sans commit | En continu |
| Accès | Comptes nominatifs sur Splunk, n8n et IRIS, aucun compte partagé | À chaque arrivée ou départ |

```
| tstats latest(_time) as dernier where index=main by host sourcetype
| eval minutes_silence=round((now()-dernier)/60)
| where minutes_silence > 60
| convert ctime(dernier)
```

## Maintien en condition de détection (MCD)

### Cycle de vie d'une règle

1. **draft** : le YAML pseudo-Sigma est rédigé dans `Detection/` (logique, sources, exclusions, contournements connus, réponse, pivots).
2. **test** : l'attaque est rejouée dans le lab et l'alerte est vérifiée jusque dans IRIS. La preuve va dans `Tests/validation_environnement/`. Si la technique n'est pas rejouable, on relit la configuration de journalisation pour prouver que l'événement est bien collecté.
3. **production** : l'alerte est enregistrée dans SA_BUILD avec la configuration standard, puis commitée.
4. **revue** : après chaque faux positif, après chaque incident, puis à la fin du RUN.

Configuration standard d'une alerte :

| Paramètre | Valeur |
|---|---|
| Titre | `[BUILD] [SÉVÉRITÉ] Nom de la règle` |
| Type | Scheduled, cron `*/5 * * * *` |
| Fenêtre | `earliest=-10m@m`, `latest=-5m@m` |
| Déclenchement | Number of Results > 0, Once |
| Throttle | 1h |
| Action | Webhook `http://soc_n8n:5678/webhook/alert` |
| Permission | Shared in App (SA_BUILD) |

### Gestion des exclusions

- Toute exclusion est écrite dans le YAML de la règle avec sa justification, sa date et son auteur, puis reportée dans la requête Splunk (ou dans un lookup CSV `dm_xx_nnn_exclusions.csv`).
- Une exclusion vise l'objet le plus étroit possible (chemin complet + compte + hôte), jamais un nom de processus seul, car l'attaquant peut l'usurper.
- Toute modification de règle est suivie d'un nouveau test unitaire, pour vérifier qu'elle détecte toujours l'attaque.

### Limites connues de la plateforme

- **Throttle global.** Splunk 8.0.2 ne permet pas de throttle par champ : une seconde occurrence sur un autre hôte dans la même heure ne redéclenche pas l'alerte.
- **Délai de détection.** La fenêtre `-10m@m` à `-5m@m` introduit un délai de 5 à 15 minutes entre l'événement et l'alerte, à intégrer dans le calcul des SLA.
- **Résultat vide trompeur.** Un résultat vide peut venir d'un événement exclu par la configuration Sysmon, et non d'un défaut de la requête. Vérifier d'abord la présence du processus avec `EventCode=1 | stats count by Image`.
- **Exclusions Sysmon du lab.** La configuration Sysmon du lab ne journalise pas `certutil`, `mshta` ni `regsvr32`, et ne collecte pas l'EventCode 10 (accès à LSASS).

### Veille

Les sources CTI et detection engineering du sujet (Sigma, Splunk Attack Data, MITRE D3FEND, SpecterOps, Unit42, Talos, CrowdStrike, Evtx attack samples) alimentent la liste des règles à ajouter.
