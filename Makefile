COMPOSE = docker compose
SIMULATORS = normal-readonly normal-jdupont normal-amir attacker-bruteforce attacker-stuffing

.PHONY: up attack check demo logs down test lint sast

up:
	$(COMPOSE) up -d --build --wait

attack:
	$(COMPOSE) --profile attack up -d --build $(SIMULATORS)
	$(COMPOSE) --profile attack wait $(SIMULATORS)

check:
	$(COMPOSE) --profile check run --rm --build detection-check

demo: up attack check

logs:
	$(COMPOSE) logs -f api

down:
	$(COMPOSE) --profile attack --profile check down -v

test:
	pytest tests/ -v

lint:
	flake8 app/ scripts/ tests/ --max-line-length=120

sast:
	bandit -r app/ scripts/
	pip-audit -r app/requirements.txt
