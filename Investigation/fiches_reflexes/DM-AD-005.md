# DM-AD-005 – DCSync (détection par proxy)

| Champ | Valeur |
|---|---|
| ID | DM-AD-005 |
| Nom de l'alerte Splunk | [BUILD] [CRITICAL] DCSync |
| Sévérité | Critical |
| MITRE ATT&CK | T1003.006 – DCSync |
| Statut | Validée de bout en bout (Splunk vers DFIR-IRIS) |

## Description

Détecte un compte utilisateur effectuant un logon réseau (4624 type 3) sur le DC depuis une IP qui n'est ni le DC ni le SRV. C'est une détection PAR PROXY du DCSync : l'évènement canonique 4662 (avec les GUID de réplication) n'est pas collecté car le SACL d'audit n'est pas posé sur l'objet domaine. Lors des tests, la règle a détecté un secretsdump lancé depuis la Kali (192.168.20.200) récupérant le hash de krbtgt.

## Requête SPL

    index=main host="DC.test.local" EventCode=4624 Logon_Type=3
    Account_Name!="ANONYMOUS LOGON"
    Source_Network_Address!="127.0.0.1" Source_Network_Address!="::1"
    Source_Network_Address!="192.168.20.100"
    Source_Network_Address!="192.168.20.101"
    | eval compte=mvfilter(Account_Name!="-" AND NOT match(Account_Name, "\$$"))
    | stats count values(compte) as comptes by Source_Network_Address, host
    | where isnotnull(comptes)
    | sort - count

## Paramètres de l'alerte

| Champ | Valeur |
|---|---|
| Permissions | Shared in App |
| Alert type | Scheduled, */5 * * * * |
| Time Range | earliest=-15m, latest=now |
| Trigger | Number of Results > 0, Once |
| Action | Webhook vers http://soc_n8n:5678/webhook/alert |

## Logique de détection

Faute de l'évènement 4662, on surveille les logons réseau (4624 type 3) sur le DC. On exclut les comptes machine (finissant par $, via NOT match(Account_Name, "\$$")), les IP du DC et du SRV, et localhost, pour ne garder que les connexions anormales. Le filtrage des comptes machine a été ajouté après avoir repéré que SRV$ passait au travers d'un premier filtre par wildcard.

## Fiche réflexe

### Triage en 5 questions

1. Quel compte s'est connecté, et depuis quelle IP source ?
2. Ce compte a-t-il une raison légitime de se connecter au DC en réseau ?
3. L'IP source est-elle un poste d'administration connu, ou une machine inhabituelle ?
4. L'action est-elle isolée ou suivie d'autres connexions / mouvements latéraux ?
5. Le compte utilisé est-il un administrateur du domaine ? Si oui, risque maximal.

### Faux positifs fréquents

- Administrateur légitime se connectant au DC en réseau depuis un poste d'admin (faux positif résiduel assumé).
- Compte machine (SRV$, DC$) : déjà exclu par le filtre.

### Actions

- Traiter en URGENCE (Critical).
- Isoler la source, désactiver le compte utilisé.
- Préparer une DOUBLE rotation du mot de passe de krbtgt (une seule ne suffit pas).
- Considérer tout le domaine comme potentiellement compromis.
- Notification client sous 2h (SLA Critical).

## Test de validation (lab)

Exécution de impacket-secretsdump depuis la Kali pour dumper le hash de krbtgt. Résultat : connexion réseau détectée dans Splunk (192.168.20.200 / Administrator), alerte CRITICAL reçue dans DFIR-IRIS. Preuve : Tests/validation_environnement/DM-AD-005.csv et captures/DM-AD-005.png.

## Limites et écarts conception / implémentation

- IMPORTANT : ce n'est PAS la détection canonique du DCSync. Celle-ci se fait sur l'évènement 4662 avec les GUID de réplication 1131f6aa-... et 1131f6ad-..., qui nécessitent un SACL d'audit posé sur l'objet domaine (l'audit Directory Service Access seul ne suffit pas). Ce SACL n'étant pas posé dans le lab, on a opté pour une détection par proxy sur le 4624 type 3.
- Faux positif résiduel : un administrateur légitime se connectant au DC en réseau déclenche aussi la règle. Amélioration : allowlist d'IP d'admin, ou mieux, migration vers le 4662 après pose du SACL.
- Les exclusions d'IP (DC, SRV) sont spécifiques au lab : à adapter sur un vrai périmètre.
