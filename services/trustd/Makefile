.PHONY: up down logs test integration

COMPOSE ?= podman compose
COMPOSE_FILE ?= docker-compose.yml
GOCACHE ?= $(CURDIR)/.gocache

up:
	$(COMPOSE) -f $(COMPOSE_FILE) up -d db trustd keycloak redis

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=100 db trustd keycloak redis

test:
	GOCACHE=$(GOCACHE) go test ./...

integration:
	GOCACHE=$(GOCACHE) go test -tags=integration ./...
