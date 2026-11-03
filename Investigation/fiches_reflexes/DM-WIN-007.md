# DM-WIN-007 - Effacement des journaux d'evenements (HIGH)

ATT&CK : T1070.001 | Auteur : Amelie Sauvan-Magnet

## Ce que l'alerte veut dire
Quelqu'un a vide un journal Windows (Security, System...) ou lance une commande
d'effacement. C'est presque toujours une tentative d'effacer des traces apres intrusion.

## A verifier en premier (triage)
- Quel compte a fait l'effacement, et quel journal ?
- L'actif touche est-il critique (DC, bastion) ? Si oui, la severite monte.
- Une maintenance etait-elle prevue a cette heure ? (a confirmer avec le client)

## Pivots d'investigation
- Activite du compte juste avant : index=main source="WinEventLog:Security" Account_Name="<compte>" earliest=-1h | stats count by ComputerName EventCode
- Ce qui s'est passe sur la machine avant l'effacement : index=main host="<machine>" earliest=-1h | stats count by source EventCode

## Faux positif probable si
- Maintenance planifiee confirmee par le client. On garde quand meme une trace.

## Si c'est confirme
- Endiguement : isoler l'hote, s'appuyer sur la copie centralisee Splunk.
- Notification client : SLA HIGH -> sous 2h.
