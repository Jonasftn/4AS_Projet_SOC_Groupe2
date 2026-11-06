# Règle DM-NET-001 : Scan de ports

| Champ | Valeur |
|---|---|
| Règle | DM-NET-001 — `[BUILD] [MEDIUM] Scan de ports horizontal et vertical` |
| MITRE | T1046 — Discovery |
| Sévérité | MEDIUM |
| SLA qualification | MEDIUM : 8 h |
| Source | Suricata, `event_type=flow` |
| Auteur | Groupe 2 — Youssef |

## 1. Ce que l’alerte signifie

Une source a contacté plus de 100 ports différents d’une même machine (scan vertical), ou plus de 20 hôtes internes différents sur un même port (scan horizontal), sur une fenêtre de 10 minutes. L’attaquant cherche les machines actives et les services exposés. Aucun impact direct, mais c’est souvent l’étape qui précède une exploitation ou un mouvement latéral.

## 2. Champs clés de l’alerte

- `scan_type` : `vertical` ou `horizontal`
- `src_ip` : machine à l’origine du scan
- `dest_ip` / `nb_ports` / `ports` : cible et ports touchés (scan vertical, liste limitée à 20 valeurs)
- `dest_port` / `nb_hotes` / `hotes` : port et hôtes visés (scan horizontal, liste limitée à 20 valeurs)
- `premier_evenement` / `dernier_evenement` : fenêtre de l’activité

## 3. Qualification (à faire en premier)

1. **La source est-elle connue ?** Rechercher `src_ip` dans l’inventaire et le lookup d’exclusions. Un scanner autorisé ou un outil de supervision oriente vers un faux positif.
2. **La source est-elle interne ?** Un scan interne laisse penser qu’une machine est compromise. Une source inconnue dans le réseau est un indicateur fort.
3. **Quels ports sont visés ?** 22, 445, 3389 ou 5985 indiquent une recherche d’accès distant.
4. **Des connexions ont-elles abouti ?** Vérifier si la source a ensuite échangé des données avec les ports ouverts.
5. **La cible est-elle critique ?** Le DC, le bastion ou un compte privilégié relèvent la sévérité de +1.

## 4. Investigation — pivots

**P-SRC-IP-SCOPE — périmètre de la machine source**

```spl
index=* "<src_ip>" earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, host
| convert ctime(first) ctime(last)
```

À chercher : autres alertes BUILD sur la même source, comptes utilisés depuis cette IP.

**P-NET-CONN — connexions de la source (pivot spécifique)**

```spl
index=main sourcetype=suricata event_type=flow src_ip="<src_ip>" earliest=-24h
| stats count dc(dest_port) as nb_ports values(proto) as proto min(_time) as first max(_time) as last by dest_ip
| convert ctime(first) ctime(last)
```

À chercher : autres cibles touchées, extension du scan à d’autres machines.

**P-PROC-TREE — processus à l’origine (si la source est un poste Windows du parc)**

```spl
index=main host="<poste_source>" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : `nmap`, scripts PowerShell de balayage, binaires inconnus.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Scanner autorisé ou supervision connue | Faux positif | Ajouter `src_ip` à `DM-NET-001_exclusions.csv` avec justification, clôturer |
| Source inconnue ou outil offensif identifié | Vrai positif | Confinement (section 6), ouverture d’un cas |
| Connexions abouties ou cible critique | Vrai positif HIGH | Confinement immédiat, notification client |
| Doute sur la source | À confirmer | Contacter le propriétaire, conserver le cas ouvert |

## 6. Réponse

**Confinement**

- Bloquer l’IP source si elle est externe.
- Identifier la machine et le compte à l’origine du scan si la source est interne.

**Remédiation**

- Réduire la surface exposée : fermer les ports inutiles.
- Vérifier le filtrage entre les zones du réseau.

**À ne pas faire**

- Ne pas ignorer un scan interne.

## 7. Notification et consignation (IRIS)

- MEDIUM : pas de notification client, qualification sous 8 h. Si la sévérité passe à HIGH : notification sous 2 h, qualification sous 4 h.
- Éléments à consigner : `scan_type`, `src_ip`, `dest_ip`, `dest_port`, `nb_ports` ou `nb_hotes`, fenêtre de l’activité.
- Résultats des pivots, verdict, actions réalisées (heure, opérateur) et entrée lookup si faux positif.

## 8. Détection et validation

**Requête SPL**

```spl
index=main sourcetype=suricata event_type=flow dest_port=*
| stats dc(dest_port) as nb_ports values(dest_port) as ports min(_time) as premier_evenement max(_time) as dernier_evenement by src_ip, dest_ip
| where nb_ports>100
| eval scan_type="vertical", ports=mvindex(ports, 0, 19)
| append
    [ search index=main sourcetype=suricata event_type=flow dest_port=*
      | where cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip)
      | stats dc(dest_ip) as nb_hotes values(dest_ip) as hotes min(_time) as premier_evenement max(_time) as dernier_evenement by src_ip, dest_port
      | where nb_hotes>20
      | eval scan_type="horizontal", hotes=mvindex(hotes, 0, 19) ]
| lookup DM-NET-001_exclusions.csv src_ip OUTPUT exclude
| where isnull(exclude)
| eval premier_evenement=strftime(premier_evenement, "%F %T"), dernier_evenement=strftime(dernier_evenement, "%F %T")
| eval rule_id="DM-NET-001"
```

Fenêtre de 10 minutes évaluée toutes les 5 minutes, décalée de 5 minutes pour laisser les flows arriver. Le scan horizontal est limité aux destinations internes pour ne pas alerter sur la navigation web. Les seuils de 100 ports et 20 hôtes sont des choix de conception à ajuster en RUN.

**Tests réalisés**

| Test | Attendu | Résultat |
|---|---|---|
| Lab, Kali vers Kunai : `nmap -sS -Pn -p- 192.168.20.50` | Détection `vertical` | Validé : 65 535 ports, alerte IRIS #394 |
| Lab, 8 ports sur la même cible | Aucune détection | Validé : 8 ports vus dans Splunk, aucun résultat |
| Données d’exemple, index `test_reseau` | `vertical`, `horizontal`, rien pour la navigation web | Validé : alertes IRIS #144 et #145 |

**Limites**

Le scan horizontal n’a pas pu être testé sur de vrais logs : le lab compte trop peu de machines pour dépasser 20 hôtes. Contournements connus : scan lent, réparti sur plusieurs sources, ou limité sous les seuils. Un scan horizontal vers Internet n’est pas couvert. Suricata ne voit que le trafic qui passe par sa sonde.
