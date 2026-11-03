# DM-AD-004 - Password spraying (MEDIUM)

ATT&CK : T1110.003 | Auteur : Amelie Sauvan-Magnet

## Ce que l'alerte veut dire
Une meme source a echoue a se connecter sur beaucoup de comptes differents en peu de
temps, avec peu d'essais par compte : signature d'un spray de mot de passe.

## A verifier en premier (triage)
- Quelle IP source, et combien de comptes distincts vises ?
- Un de ces comptes a-t-il fini par reussir (4624 depuis la meme IP juste apres) ?
- La source est-elle interne (poste compromis) ou externe ?

## Pivots d'investigation
- Succes depuis la meme IP : index=main source="WinEventLog:Security" EventCode=4624 Source_Network_Address="<ip>" | stats values(Account_Name) by _time
- Comptes vises : index=main EventCode IN (4625,4771,4776) Source_Network_Address="<ip>" | stats dc(Account_Name)

## Faux positif probable si
- Appli / compte de service mal configure qui rejoue un vieux mot de passe. A exclure par compte source.

## Si c'est confirme
- Endiguement : bloquer l'IP source, reset des comptes ou un 4624 a suivi.
- Notification client : SLA MEDIUM -> qualification sous 8h.
