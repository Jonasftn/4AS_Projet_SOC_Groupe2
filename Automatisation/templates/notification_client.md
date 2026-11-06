# Template — Notification client (HIGH / CRITICAL)

> Généré automatiquement par le workflow n8n pour toute alerte HIGH ou CRITICAL.
> SLA de notification : **2 heures** après détection. Brouillon à valider par un analyste avant envoi.
> Les champs `{{ ... }}` sont remplis depuis le ticket IRIS.

---

**Objet :** [SOC AEGIS] Alerte de sécurité {{severite}} — {{client}} — Incident {{incident_id}}

Bonjour,

Dans le cadre de la supervision de sécurité de votre système d'information, notre SOC a détecté un événement nécessitant votre attention.

**Résumé**
- **Niveau de sévérité :** {{severite}}
- **Date et heure de détection :** {{date_detection}}
- **Règle déclenchée :** {{nom_regle}}
- **Technique (MITRE ATT&CK) :** {{technique_attack}}

**Éléments concernés**
- **Hôte :** {{hote}}
- **Compte impliqué :** {{compte}}
- **Source (IP) :** {{ip_source}}

**Ce que nous savons**
{{description_courte}}

**Ce que nous ne savons pas encore**
L'investigation est en cours. Nous n'avons pas encore confirmé {{points_a_confirmer}}.

**Recommandation immédiate**
{{action_recommandee}}

**Ce qu'il ne faut PAS faire**
Ne pas éteindre ni réinitialiser la machine concernée avant notre accord : cela détruirait des éléments d'investigation.

**Prochaine étape**
Nous vous transmettrons un premier rapport de qualification sous **{{delai_qualification}}** (SLA : 4h pour HIGH/CRITICAL).

Pour toute question, répondez à ce message ou contactez l'astreinte SOC.

Cordialement,
L'équipe SOC — AEGIS CyberProtect
