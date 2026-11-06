# Projet SOC 5A-4AS — Groupe 2

Mini SOC d'AEGIS CyberProtect pour le client Dunder Mifflin : règles de détection Splunk, automatisation n8n vers DFIR-IRIS, processus d'investigation et de communication client.

## Arborescence

| Dossier | Contenu |
|---|---|
| [`Detection/`](Detection/) | Règles de détection au format pseudo-Sigma (YAML), par domaine : [Active Directory](Detection/Active_Directory/), [Windows](Detection/Windows/), [Linux](Detection/Linux/), [Réseau](Detection/Network/) |
| [`Investigation/`](Investigation/) | Workflow d'investigation, [librairie de pivots](Investigation/pivots.md), [fiches réflexes](Investigation/fiches_reflexes/) |
| [`Tests/`](Tests/) | Preuves de validation des règles dans le lab (exports CSV Splunk, captures DFIR-IRIS) |
| [`Documentation/`](Documentation/) | Architecture et sources, matrices de priorisation et de communication, MCO/MCD, organisation |
| `Automatisation/` | Workflows n8n, templates de notification, scripts (à venir) |
| [`SA_BUILD/`](SA_BUILD/) | Export de l'application Splunk : [`local/savedsearches.conf`](SA_BUILD/local/savedsearches.conf) (alertes `[BUILD]`), [`metadata/local.meta`](SA_BUILD/metadata/local.meta), dashboards (à venir) |

## Chaîne de traitement

Splunk (app SA_BUILD, règles planifiées toutes les 5 min) → webhook n8n → alerte DFIR-IRIS → triage et investigation → notification et rapports client sur Teams.

## Équipe

Tim LEVADOUX, Amelie SAUVAN-MAGNET, Nathan SACIER, Jonas FONTAINE-DEMAY, Killian Munt-Buron & Youssef Moutaleb.
