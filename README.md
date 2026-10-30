# Security Lab DevSecOps

Lab de sécurité local : une API conteneurisée surveillée par un SIEM open source
(Loki, Grafana Alloy, Grafana) qui détecte des attaques simulées, avec un
pipeline GitLab CI DevSecOps.

## Lancement

Prérequis : Docker et Docker Compose v2.

```
cp .env.example .env    # puis choisir un mot de passe Grafana
make demo
```

Sans `make` :

```
docker compose up -d --build --wait
docker compose --profile attack up -d --build normal-readonly normal-jdupont normal-amir attacker-bruteforce attacker-stuffing
docker compose --profile attack wait normal-readonly normal-jdupont normal-amir attacker-bruteforce attacker-stuffing
docker compose --profile check run --rm --build detection-check
```

- Grafana : http://localhost:3000 (admin / mot de passe du `.env`)
- Alertes e-mail (Mailpit) : http://localhost:8025
- API : http://localhost:8080

Arrêt : `make down`

## Détections

| Règle | Déclencheur |
|---|---|
| `brute_force_login` | 5 échecs de connexion ou plus depuis une même IP en 5 min |
| `multiple_accounts_same_ip` | 3 comptes distincts ou plus connectés depuis une même IP en 10 min |

Les règles sont dans `siem/detection_rules/`, les runbooks dans `siem/runbooks/`.

## Pipeline GitLab CI

Lint (flake8), tests (pytest), SAST (Bandit), audit des dépendances (pip-audit),
scan de configuration et d'image (Trivy), puis test de bout en bout qui rejoue
les attaques et vérifie leur détection.

Le pipeline s'exécute sur GitLab : [voir les pipelines](https://gitlab.com/amir-doudou/security-lab-devsecops/-/pipelines).

## Stack

Python, Flask, nginx, Docker, Docker Compose, Grafana, Loki, Grafana Alloy,
GitLab CI/CD, Trivy, Bandit.
