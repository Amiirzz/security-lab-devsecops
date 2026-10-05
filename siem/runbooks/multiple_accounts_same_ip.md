# Runbook : connexions reussies sur plusieurs comptes depuis une meme IP

**Declencheur** : 3 comptes distincts ou plus authentifies avec succes depuis une meme IP en 10 minutes.
Signature typique de credential stuffing (identifiants fuites reutilises) ou d'une machine
partagee compromise.

## Investigation
1. Grafana > Explore : lancer `siem/hunting/accounts_per_ip.logql` pour lister les comptes concernes.
2. Distinguer un faux positif legitime (NAT d'entreprise, proxy connu) d'une IP inconnue.
3. Examiner l'activite `resource_access` des comptes apres la connexion (`ip_timeline.logql`).

## Reponse
- Invalider les sessions des comptes concernes et forcer un changement de mot de passe.
- Si l'IP est legitime (NAT), l'ajouter a une liste d'exclusion documentee dans la regle.
