.PHONY: venv install test lint run-api run-web clean help

help:
	@echo "PHP Security Scanner - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  venv       - Create virtual environment"
	@echo "  install    - Install dependencies"
	@echo "  test       - Run tests"
	@echo "  lint       - Run code quality checks"
	@echo "  run-api    - Start FastAPI server"
	@echo "  run-web    - Start web interface"
	@echo "  clean      - Clean build artifacts"

venv:
	python3 -m venv .venv
	@echo "✓ Virtual environment created"
	@echo "Activate with: source .venv/bin/activate"

install:
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo "✓ Dependencies installed"

test:
	.venv/bin/pytest -v --tb=short

test-cov:
	.venv/bin/pytest --cov=. --cov-report=html --cov-report=term

lint:
	.venv/bin/ruff check .

run-api:
	.venv/bin/uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

run-web:
	.venv/bin/python web_interface.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
	@echo "✓ Cleaned build artifacts"
