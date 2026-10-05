# Runbook : force brute sur l'authentification

**Declencheur** : 5 echecs de connexion ou plus depuis une meme IP en 5 minutes.
L'IP source figure dans le label `source_ip` de l'alerte (Grafana > Alerting et e-mail).

## Investigation
1. Grafana > Explore (source Loki) : lancer `siem/hunting/ip_timeline.logql` en remplacant l'IP.
2. Verifier si un `auth_success` suit la serie d'echecs depuis la meme IP (compromission probable).
3. Identifier les comptes cibles (`username`).

## Reponse
- Bloquer l'IP au niveau du reverse proxy (`deny <ip>;` dans `proxy/nginx.conf`).
- En cas de connexion reussie : invalider les sessions et changer le mot de passe du compte.
