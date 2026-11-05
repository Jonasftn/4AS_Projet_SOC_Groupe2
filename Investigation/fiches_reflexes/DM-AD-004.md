# DM-AD-004 – Password spraying

| Champ | Valeur |
|---|---|
| ID | DM-AD-004 |
| Nom de l'alerte Splunk | [BUILD] [MEDIUM] Password spraying |
| Sévérité | Medium |
| MITRE ATT&CK | T1110.003 – Password Spraying |
| Statut | Validée de bout en bout (Splunk vers DFIR-IRIS) |

## Description

Détecte une même source réseau qui échoue à s'authentifier sur de nombreux comptes différents en peu de temps. Lors des tests, la règle a détecté un spray lancé depuis la Kali (192.168.20.200) visant 8 comptes du domaine avec un seul mot de passe, soit 14 échecs regroupés.

## Requête SPL

    index=main source="WinEventLog:Security" EventCode=4625
    | eval compte=mvfilter(Account_Name!="-" AND Account_Name!="*$")
    | stats dc(compte) as nb_comptes values(compte) as comptes count as nb_echecs by Source_Network_Address, host
    | where nb_comptes >= 5
    | sort - nb_comptes

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, */5 * * * * |
| Time Range | earliest=-15m, latest=now |
| Trigger | Number of Results > 0, Once |
| Action | Webhook vers http://soc_n8n:5678/webhook/alert |

## Logique de détection

On regroupe les échecs d'authentification (EventCode 4625) par IP source sur une fenêtre de 15 minutes. Le seuil porte sur le nombre de comptes DISTINCTS visés (dc(Account_Name) superieur ou egal a 5), et non sur le nombre d'essais. C'est ce qui distingue le password spraying d'un brute force classique.

## Fiche réflexe

### Triage en 5 questions

1. Quelle IP source, et combien de comptes distincts visés ?
2. Un de ces comptes a-t-il fini par réussir (4624 depuis la même IP juste après) ? Si oui, la sévérité monte fortement.
3. La source est-elle interne (poste compromis) ou externe ?
4. Les comptes visés sont-ils des comptes réels du domaine (liste cohérente = reconnaissance préalable) ?
5. L'attaque est-elle isolée ou suivie d'autres actions depuis la même IP ?

### Faux positifs fréquents

- Scanner de vulnérabilités ou outil de supervision.
- Compte de service mal configuré qui rejoue un ancien mot de passe (à exclure par IP source).

### Actions

- Bloquer l'IP source.
- Surveiller les comptes visés, forcer le reset de tout compte où un 4624 a suivi.
- Qualification sous 8h (SLA Medium).

## Test de validation (lab)

Spray lancé depuis la Kali avec crackmapexec (un mot de passe sur 6 comptes du domaine). Résultat : une ligne regroupée (IP 192.168.20.200, 8 comptes visés), alerte reçue dans DFIR-IRIS. Preuve : Tests/validation_environnement/DM-AD-004.csv et captures/DM-AD-004.png.

## Limites et écarts conception / implémentation

- Un spraying très lent (moins de 5 comptes par fenêtre de 15 min) ou réparti sur plusieurs IP sources passe sous le seuil. Angle mort assumé à surveiller en RUN.
- Le champ Account_Name d'un 4625 peut être multivaleur (compte visé + compte système) : à vérifier si le comptage de comptes distincts semble gonflé.
