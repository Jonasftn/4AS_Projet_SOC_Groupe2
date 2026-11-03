# DM-AD-008 - Delegation Kerberos (HIGH)

ATT&CK : T1134.005 | Auteur : Amelie Sauvan-Magnet

## Ce que l'alerte veut dire
Un attribut de delegation Kerberos a ete modifie sur un objet (ordinateur ou utilisateur).
Mal configuree, une delegation permet d'usurper un utilisateur sur un service.

## A verifier en premier (triage)
- Quel objet modifie, quel attribut (msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity) ?
- Quel compte a fait la modification ? A-t-il le droit ?
- La modification correspond-elle a un changement d'infra legitime connu ?

## Pivots d'investigation
- Qui a modifie : index=main source="WinEventLog:Security" EventCode=5136 | table _time SubjectUserName ObjectDN AttributeLDAPDisplayName AttributeValue
- L'objet delegue a-t-il ensuite demande des tickets (4769) ? -> signe d'exploitation.

## Faux positif probable si
- Changement d'administration legitime (nouveau service). A confirmer avec le client et exclure par objet si recurrent.

## Si c'est confirme
- Endiguement : annuler la delegation, desactiver le compte modificateur si non autorise.
- Notification client : SLA HIGH -> sous 2h.
