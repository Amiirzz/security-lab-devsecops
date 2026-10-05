# Requetes de chasse (LogQL)

A lancer dans Grafana > Explore, source **Loki**.

| Fichier | Type de requete | Usage |
|---|---|---|
| `top_failing_ips.logql` | Instant | Top 10 des IP par echecs d'authentification sur 24 h |
| `accounts_per_ip.logql` | Instant | Nombre de comptes distincts authentifies par IP sur 24 h |
| `ip_timeline.logql` | Logs | Chronologie de l'activite d'une IP (remplacer l'IP dans la requete) |
