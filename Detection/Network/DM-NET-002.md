# Règle DM-NET-002 : Beaconing C2

| Champ | Valeur |
|---|---|
| Règle | DM-NET-002 — `[BUILD] [HIGH] Beaconing C2 - connexions regulieres vers l’exterieur` |
| MITRE | T1071 — Command and Control |
| Sévérité | HIGH |
| SLA | Notification client : 2 h — Qualification : 4 h |
| Source | Suricata, `event_type=flow` |
| Auteur | Groupe 2 — Youssef |

## 1. Ce que l’alerte signifie

Une machine contacte une même destination externe et un même port à un rythme très régulier : au moins 12 connexions sur 24 heures, avec un coefficient de variation inférieur à 0,15. Ce rythme peut indiquer un implant qui demande régulièrement ses ordres à un serveur C2. Il peut aussi venir d’un service légitime : l’alerte demande donc une vérification.

## 2. Champs clés de l’alerte

- `src_ip` : machine potentiellement infectée
- `dest_ip` / `dest_port` : destination et port contactés
- `nb_connexions` : nombre de connexions sur la fenêtre
- `intervalle_moyen` / `ecart_type` / `cv` : rythme moyen et régularité des connexions
- `octets_envoyes_moyen` : volume moyen envoyé par connexion
- `premier_evenement` / `dernier_evenement` : fenêtre de l’activité

## 3. Qualification (à faire en premier)

1. **La destination est-elle connue ?** Vérifier `dest_ip` dans l’inventaire, le lookup d’exclusions et la réputation de l’adresse.
2. **Le service est-il légitime ?** Mises à jour, NTP, télémétrie, supervision ou Tailscale orientent vers un faux positif.
3. **Quel processus est à l’origine ?** Un binaire inconnu ou lancé depuis un dossier temporaire est un indicateur fort.
4. **Le rythme est-il anormal pour cette machine ?** Vérifier depuis quand la communication existe.
5. **La machine a-t-elle d’autres alertes ?** Plusieurs règles sur la même source relèvent la sévérité de +1.

## 4. Investigation — pivots

**P-NET-CONN — connexions vers la destination (pivot spécifique)**

```spl
index=main sourcetype=suricata event_type=flow dest_ip="<dest_ip>" earliest=-24h
| stats count sum(flow.bytes_toserver) as envoye sum(flow.bytes_toclient) as recu min(_time) as first max(_time) as last by src_ip, dest_port
| convert ctime(first) ctime(last)
```

À chercher : autres machines qui contactent la même destination, hausse du volume envoyé.

**P-PROC-TREE — processus à l’origine de la connexion**

```spl
index=main host="<hote_source>" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-24h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : binaire inconnu, dossier temporaire, parent inhabituel. Sur Linux, utiliser les logs Kunai de l’hôte.

**P-SRC-IP-SCOPE — périmètre de la machine source**

```spl
index=* "<src_ip>" earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, host
| convert ctime(first) ctime(last)
```

À chercher : autres alertes BUILD, connexions internes après le début du beacon.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Service légitime identifié | Faux positif | Ajouter `dest_ip` à `DM-NET-002_exclusions.csv` avec justification, clôturer |
| Processus inconnu ou destination suspecte | Vrai positif | Confinement (section 6), notification client |
| Actif critique ou activité étendue | Vrai positif CRITICAL | Confinement immédiat, escalade |
| Doute sur la destination | À confirmer | Traiter comme malveillant dans le délai SLA, question au client |

## 6. Réponse

**Confinement**

- Isoler l’hôte source.
- Bloquer la destination au pare-feu.

**Remédiation**

- Supprimer l’implant.
- Renouveler les identifiants de l’hôte.

**À ne pas faire**

- Ne pas couper le flux avant d’avoir identifié le processus.

## 7. Notification et consignation (IRIS)

- HIGH : notification client sous 2 h, qualification sous 4 h, rapport final sous 72 h.
- Éléments à consigner : `src_ip`, `dest_ip`, `dest_port`, `nb_connexions`, `intervalle_moyen`, `cv`, fenêtre de l’activité.
- Résultats des pivots, verdict, actions réalisées (heure, opérateur) et entrée lookup si faux positif.

## 8. Détection et validation

**Requête SPL**

```spl
index=main sourcetype=suricata event_type=flow
| where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip) OR cidrmatch("127.0.0.0/8", dest_ip) OR cidrmatch("169.254.0.0/16", dest_ip) OR cidrmatch("224.0.0.0/4", dest_ip) OR dest_ip="255.255.255.255" OR like(dest_ip, "%:%"))
| eval heure_flux=coalesce(strptime('flow.start', "%Y-%m-%dT%H:%M:%S.%6N%z"), _time)
| sort 0 src_ip dest_ip dest_port heure_flux
| streamstats current=f last(heure_flux) as heure_precedente by src_ip, dest_ip, dest_port
| eval delta=heure_flux-heure_precedente
| stats count as nb_connexions avg(delta) as intervalle_moyen stdev(delta) as ecart_type avg(flow.bytes_toserver) as octets_envoyes_moyen min(heure_flux) as premier_evenement max(heure_flux) as dernier_evenement by src_ip, dest_ip, dest_port
| eval cv=round(ecart_type/intervalle_moyen, 3), intervalle_moyen=round(intervalle_moyen, 1), octets_envoyes_moyen=round(octets_envoyes_moyen, 0)
| where nb_connexions>=12 AND cv<0.15 AND intervalle_moyen>10
| lookup DM-NET-002_exclusions.csv dest_ip OUTPUT exclude
| where isnull(exclude)
| eval premier_evenement=strftime(premier_evenement, "%F %T"), dernier_evenement=strftime(dernier_evenement, "%F %T")
| eval rule_id="DM-NET-002"
```

Exécution toutes les heures sur 24 heures. Au moins 12 connexions, intervalle moyen supérieur à 10 secondes et coefficient de variation inférieur à 0,15. Les destinations internes, multicast, lien local et IPv6 sont exclues. Ces seuils sont des choix de conception à ajuster en RUN.

**Tests réalisés**

| Test | Attendu | Résultat |
|---|---|---|
| Lab, Kunai vers `1.1.1.1:80`, 30 requêtes toutes les 15 s | Une détection | Validé : 30 connexions, 15,0 s, `cv` 0,000, alerte IRIS #400 |
| Données d’exemple, index `test_reseau` | Beacon détecté, trafic irrégulier et multicast ignorés | Validé : `cv` 0,030, alerte IRIS #147 |

**Limites**

Contournements connus : jitter élevé, intervalles supérieurs à environ 2 heures, connexion longue unique, destination interne, rotation de domaines ou d’IP. Suricata ne donne pas le processus à l’origine : il faut le chercher dans les logs de l’hôte.
