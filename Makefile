.PHONY: install dev test smoke build

install:
	pip install -e .
	pip install pytest httpx

dev:
	ENV_FILE=./.env.dev uvicorn agent.main:create_app --factory --reload --host 127.0.0.1 --port 18443

test:
	pytest -q

smoke:
	python scripts/smoke.py

# Linux binaries via Docker Buildx (default: gnu/amd64)
build:
	bash scripts/build.sh

# All targets: gnu/musl × amd64/arm64
build-all:
	bash scripts/build.sh --all
