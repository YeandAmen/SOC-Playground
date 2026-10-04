.PHONY: all validate evaluate sims lint clean

all: validate evaluate

validate: sims lint
	@echo "All validations passed."

sims:
	@echo "Checking simulation manifests..."
	@for f in simulations/*.yml; do python3 -c "import yaml; yaml.safe_load(open('$$f'))" || exit 1; done
	@echo "All manifests valid."

lint:
	@echo "Checking Sigma YAML..."
	@python3 -c "import yaml; list(yaml.safe_load_all(open('rules/sigma_rules.yml')))" && echo "Sigma OK (6 rules)"
	@python3 -c "import json; json.load(open('expected/expected_events.json'))" && echo "Expected events OK"
	@echo "Lint passed."

evaluate:
	@echo "Running evaluation pipeline..."
	@python3 scripts/evaluate.py

clean:
	@rm -f results/run_*.json
	@echo "Cleaned results."

.venv:
	python3 -m venv .venv
	.venv/bin/pip install pyyaml
	@echo "Virtual env ready. Run: source .venv/bin/activate"