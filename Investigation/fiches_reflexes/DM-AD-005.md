# DM-AD-005 - DCSync (CRITICAL)

ATT&CK : T1003.006 | Auteur : Amelie Sauvan-Magnet

## Ce que l'alerte veut dire
Un compte qui n'est pas un controleur de domaine a demande la replication des secrets
de l'annuaire. C'est une extraction des hash du domaine (dont krbtgt).

## A verifier en premier (triage)
- Quel compte (SubjectUserName) ? Est-il cense avoir les droits de replication ?
- Depuis quelle machine / IP (pivot 4624 meme Logon_Id) ?
- Isole, ou suivi d'autres actions ?

## Pivots d'investigation
- IP source de la session : index=main source="WinEventLog:Security" EventCode=4624 Logon_Id="<logonid>" | table Source_Network_Address Account_Name
- Historique du compte : index=main Account_Name="<compte>" | stats count by EventCode ComputerName

## Faux positif probable si
- Vrai DC (compte machine en $) -> deja exclu par la regle. Outil de supervision AD legitime -> a exclure par compte si identifie.

## Si c'est confirme
- Endiguement : isoler la source, desactiver le compte, preparer une rotation krbtgt (x2).
- Notification client : SLA CRITICAL -> sous 2h, qualification sous 4h.
