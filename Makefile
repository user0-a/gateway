PY ?= python3

.PHONY: dev test bootstrap

dev:
	uvicorn gateway.app:app --reload --host 127.0.0.1 --port 8001

test:
	$(PY) -m pytest -q

bootstrap:
	$(PY) scripts/bootstrap.py
