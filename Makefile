# EXPOSE Monorepo Makefile

.PHONY: help dev down build test clean

help:
	@echo "EXPOSE Development Commands:"
	@echo "  make dev    - Boot the complete stack locally with docker compose"
	@echo "  make down   - Stop and tear down all containers"
	@echo "  make build  - Rebuild all container images"
	@echo "  make test   - Run test suite"

dev:
	docker compose -f infrastructure/docker/docker-compose.yml up --build

down:
	docker compose -f infrastructure/docker/docker-compose.yml down

build:
	docker compose -f infrastructure/docker/docker-compose.yml build

test:
	@echo "Running Phase 1 foundation tests..."
	cd apps/api && go test -v ./...
