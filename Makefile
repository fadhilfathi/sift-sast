.PHONY: help install lint fmt types test cov gate eval eval-dry cost clean

PY := uv run

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "%-12s %s\n", $$1, $$2}'

install: ## Sync the dev environment
	uv sync --extra dev

lint: ## Ruff check + format check
	$(PY) ruff check .
	$(PY) ruff format --check .

fmt: ## Apply ruff fixes and formatting
	$(PY) ruff check --fix .
	$(PY) ruff format .

types: ## mypy strict
	$(PY) mypy

test: ## pytest, excluding tests that spend money
	$(PY) pytest -m "not llm"

cov: ## pytest with coverage
	$(PY) pytest -m "not llm" --cov --cov-report=term-missing --cov-report=xml

gate: lint types test ## Full local gate. Must pass before any push.

eval-dry: ## Estimate eval cost and call count without spending anything
	$(PY) sift eval --dry-run

eval: ## Run the eval suite and write evals/REPORT.md
	$(PY) sift eval --report evals/REPORT.md

cost: ## Token spend and latency from the last eval run
	$(PY) sift cost

clean:
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage coverage.xml dist build
