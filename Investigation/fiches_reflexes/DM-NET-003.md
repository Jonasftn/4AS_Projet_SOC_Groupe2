# Règle DM-NET-003 : DNS tunneling

| Champ | Valeur |
|---|---|
| Règle | DM-NET-003 — `[BUILD] [MEDIUM] DNS tunneling - volume et longueur anormaux` |
| MITRE | T1048.003 — Exfiltration |
| Sévérité | MEDIUM |
| SLA qualification | MEDIUM : 8 h |
| Source | Sysmon 22 (requêtes DNS) |
| Auteur | Groupe 2 — Youssef |

## 1. Ce que l’alerte signifie

Une machine Windows a demandé plus de 100 noms différents pour un même domaine parent en 10 minutes, avec des sous-domaines longs en moyenne (plus de 20 caractères). Ce comportement peut cacher un canal C2 ou une exfiltration de données dans des requêtes DNS. Certains services légitimes peuvent produire un trafic proche.

## 2. Champs clés de l’alerte

- `ComputerName` : machine à l’origine des requêtes
- `domain` : domaine parent interrogé
- `nb_uniques` : nombre de noms différents
- `longueur_moyenne` / `longueur_max` : longueur des sous-domaines
- `images` : processus à l’origine des requêtes
- `premier_evenement` / `dernier_evenement` : fenêtre de l’activité

## 3. Qualification (à faire en premier)

1. **Le domaine est-il connu ?** Vérifier `domain` dans le lookup d’exclusions. CDN, services cloud et antivirus sont des faux positifs possibles.
2. **Quel processus envoie les requêtes ?** Un outil de script ou un binaire inconnu est plus suspect qu’un navigateur.
3. **Les sous-domaines semblent-ils encodés ?** De longues chaînes aléatoires peuvent contenir des données.
4. **Quel volume et sur quelle durée ?** Regarder la fenêtre et le nombre de requêtes.
5. **La machine a-t-elle d’autres alertes ?** Plusieurs règles sur le même hôte relèvent la sévérité de +1.

## 4. Investigation — pivots

**P-DNS-QUERIES — requêtes vers le domaine (pivot spécifique)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryName="*<domain>" earliest=-24h
| table _time ComputerName User Image QueryName
| sort _time
```

À chercher : autres machines touchées, processus, forme des sous-domaines.

**P-PROC-TREE — processus à l’origine des requêtes**

```spl
index=main host="<hote>" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1h
| table _time User ParentImage Image CommandLine
| sort _time
```

À chercher : commande lancée, processus parent, script ou binaire inconnu.

## 5. Décision

| Constat | Verdict | Suite |
|---|---|---|
| Domaine légitime identifié | Faux positif | Ajouter `domain` à `DM-NET-003_exclusions.csv` avec justification, clôturer |
| Domaine inconnu et processus suspect | Vrai positif | Confinement (section 6), ouverture d’un cas |
| Données sensibles potentiellement exfiltrées | Vrai positif HIGH | Confinement immédiat, notification client |
| Doute sur le domaine | À confirmer | Contacter le propriétaire, conserver le cas ouvert |

## 6. Réponse

**Confinement**

- Bloquer le domaine au DNS.
- Isoler l’hôte.

**Remédiation**

- Mettre en place un filtrage DNS sortant.

**À ne pas faire**

- Ne pas résoudre le domaine depuis un poste du client.

## 7. Notification et consignation (IRIS)

- MEDIUM : pas de notification client, qualification sous 8 h. Si la sévérité passe à HIGH : notification sous 2 h, qualification sous 4 h.
- Éléments à consigner : `ComputerName`, `domain`, `nb_uniques`, `longueur_moyenne`, `images`, fenêtre de l’activité.
- Résultats des pivots, verdict, actions réalisées (heure, opérateur) et entrée lookup si faux positif.

## 8. Détection et validation

**Requête SPL**

```spl
index=main source="wineventlog:microsoft-windows-sysmon/operational" EventCode=22
| eval requete=lower(trim(QueryName, "."))
| where NOT match(requete, "[.](in-addr|ip6)[.]arpa$")
| rex field=requete "^(?<sous_domaine>.+?)[.](?<domain>[^.]+[.](?:(?:co|com|org|net|gov|ac|edu)[.][a-z]{2}|[^.]+))$"
| where isnotnull(domain)
| eval longueur=len(sous_domaine)
| stats dc(requete) as nb_uniques avg(longueur) as longueur_moyenne max(longueur) as longueur_max values(Image) as images min(_time) as premier_evenement max(_time) as dernier_evenement by ComputerName, domain
| eval longueur_moyenne=round(longueur_moyenne, 1)
| where nb_uniques>100 AND longueur_moyenne>20
| lookup DM-NET-003_exclusions.csv domain OUTPUT exclude
| where isnull(exclude)
| eval premier_evenement=strftime(premier_evenement, "%F %T"), dernier_evenement=strftime(dernier_evenement, "%F %T")
| eval rule_id="DM-NET-003"
```

Exécution toutes les 10 minutes sur une fenêtre de 10 minutes, décalée de 10 minutes. La règle combine le nombre de noms uniques et leur longueur moyenne pour limiter le bruit. Les zones `arpa` sont exclues. Les seuils sont des choix de conception à ajuster en RUN.

**Tests réalisés**

| Test | Attendu | Résultat |
|---|---|---|
| Lab, SRV : 150 noms aléatoires vers `tunnel-test.invalid` | Détection | Validé : 150 noms, 36 caractères en moyenne, `powershell.exe`, alerte IRIS #113 |
| Sous-domaines de 15 caractères | Aucune détection | Non testé |

**Limites**

Contournements connus : faible débit, sous-domaines courts, répartition sur plusieurs domaines parents, ou outil qui ne passe pas par le client DNS Windows. Les hôtes Linux ne sont pas couverts par Sysmon.
