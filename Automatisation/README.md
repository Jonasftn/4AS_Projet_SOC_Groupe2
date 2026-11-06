# Automatisation — SOC Groupe 2

Ce dossier regroupe l'outillage qui automatise le traitement des alertes : de la détection Splunk jusqu'à la création du ticket dans DFIR-IRIS.

## Chaîne d'automatisation

```
Règle Splunk (alerte planifiée, action Webhook)
        │   POST  http://soc_n8n:5678/webhook/alert
        ▼
n8n : workflow « webhook_alert »
        ▼
Ticket d'alerte créé dans DFIR-IRIS (avec la bonne sévérité)
```

## Workflow n8n : `webhook_alert`

Fichier : `n8n/webhook_alert.json`

Structure réelle du workflow (une branche par niveau de sévérité) :

```
Webhook (POST)
   ├─→ INFO - TITRE      →  INFO        ┐
   ├─→ LOW - TITRE       →  INFO1       │
   ├─→ MEDIUM - TITRE    →  MEDIUM      ├─→  DFIR-IRIS HTTP Request
   ├─→ HIGH - TITRE      →  HIGH        │     (POST /alert)
   └─→ CRITICAL - TITRE  →  CRITICAL    ┘
```

Fonctionnement :
1. **Webhook** : reçoit le POST envoyé par l'action webhook d'une alerte Splunk. Le payload contient le nom de la recherche (`[BUILD] [SEVERITE] ...`), le lien vers les résultats et le premier résultat.
2. **Nœuds « … - TITRE »** : filtrent selon le préfixe de sévérité présent dans le nom de l'alerte, pour router vers la bonne branche.
3. **Nœuds de sévérité (INFO / LOW / MEDIUM / HIGH / CRITICAL)** : construisent le ticket avec le `severity_id` IRIS correspondant et les champs issus du résultat Splunk.
4. **DFIR-IRIS HTTP Request** : point de convergence unique, crée le ticket dans IRIS via l'API.

## Mapping des sévérités

| Préfixe du nom d'alerte | Branche n8n | Sévérité IRIS |
|---|---|---|
| `[INFO]` | INFO | Informational |
| `[LOW]` | INFO1 | Low |
| `[MEDIUM]` | MEDIUM | Medium |
| `[HIGH]` | HIGH | High |
| `[CRITICAL]` | CRITICAL | Critical |

## Validation en labo

La chaîne a été validée de bout en bout : les alertes Splunk des règles testées (WMIExec, LSASS, politique d'audit, NTDS.dit, etc.) sont bien remontées comme tickets dans DFIR-IRIS avec la bonne sévérité (voir `Tests/validation_environnement/captures/`).

## Limites connues (à améliorer)

Le workflow s'arrête à la création du ticket IRIS. Ne sont **pas** encore automatisés :
- **Les pivots d'investigation** : ils restent manuels, documentés dans les fiches réflexes (`Investigation/fiches_reflexes/`) et la librairie de pivots (`Investigation/pivots.md`).
- **La notification client** : non générée par le workflow. Le format cible est fourni dans `templates/notification_client.md` et serait à brancher sur les branches HIGH/CRITICAL (ajout d'un nœud mail ou d'un dépôt de brouillon).

Ces deux points sont les axes d'amélioration prioritaires de l'automatisation.

## Contenu du dossier

| Chemin | Contenu |
|---|---|
| `n8n/webhook_alert.json` | Export du workflow (sans credentials) |
| `templates/notification_client.md` | Modèle cible de notification client (HIGH/CRITICAL) |

## Réimporter le workflow

1. Dans n8n : menu → *Import from File* → `n8n/webhook_alert.json`.
2. Recréer la credential DFIR-IRIS (clé API) dans n8n : elle n'est pas incluse dans l'export.
