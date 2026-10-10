PY ?= python3

.PHONY: dev bootstrap test mutation bench vectors report demo java-test

dev:            ## gateway on :8001
	uvicorn gateway.app:app --reload --host 127.0.0.1 --port 8001

bootstrap:      ## demo policies, agent and employees (keys in .demo_keys/)
	$(PY) scripts/bootstrap.py

test:           ## all Python tests
	$(PY) -m pytest -q

mutation:       ## disable each protection in turn; every one must be caught by a test
	$(PY) tools/mutation_check.py

bench:          ## issuance and local verification latency
	$(PY) tools/benchmark.py 500

vectors:        ## regenerate Python -> Java conformance vectors
	$(PY) tools/make_java_vectors.py

report:         ## docs/SECURITY_REPORT.md from real runs
	$(PY) tools/security_report.py

demo:           ## end-to-end demo incl. attacks (gateway :8001 and mini-bank :8000 must run)
	$(PY) scripts/agent_to_bank_demo.py --attacks

java-test:      ## Java verifier + Spring starter (needs Maven)
	cd java && mvn -q verify
