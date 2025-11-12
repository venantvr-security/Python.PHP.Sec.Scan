.PHONY: clean-venv venv install test help db-init db-migrate scan-demo

VENV_DIR := .venv
PYTHON := python3
PIP := $(VENV_DIR)/bin/pip
PYTEST := $(VENV_DIR)/bin/pytest
PYTHON_BIN := $(VENV_DIR)/bin/python

help:
	@echo "Available targets:"
	@echo ""
	@echo "Setup:"
	@echo "  clean-venv    - Remove virtual environments (venv and .venv)"
	@echo "  venv          - Create fresh virtual environment in .venv"
	@echo "  install       - Install dependencies from requirements.txt"
	@echo ""
	@echo "Testing:"
	@echo "  test          - Run all tests"
	@echo "  test-taint    - Run taint tracker tests only"
	@echo "  test-scanner  - Run scanner tests only"
	@echo ""
	@echo "Database:"
	@echo "  db-init       - Initialize database schema"
	@echo "  db-migrate    - Run database migrations"
	@echo "  db-shell      - Open database shell"
	@echo ""
	@echo "Scanning:"
	@echo "  scan-demo     - Run demo scan on tests directory"
	@echo "  clean-cache   - Clear AST cache"

clean-venv:
	@echo "Removing virtual environments..."
	rm -rf venv .venv
	@echo "Virtual environments removed."

venv: clean-venv
	@echo "Creating virtual environment in $(VENV_DIR)..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Virtual environment created."
	@echo "Installing dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "Setup complete. Activate with: source $(VENV_DIR)/bin/activate"

install:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Installing dependencies..."
	$(PIP) install -r requirements.txt
	@echo "Dependencies installed."

test:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Running all tests..."
	$(PYTEST) tests/ -v

test-taint:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Running taint tracker tests..."
	$(PYTEST) tests/test_taint_tracker.py -v

test-scanner:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Running scanner tests..."
	$(PYTEST) tests/test_scanner.py -v

db-init:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Initializing database..."
	$(PYTHON_BIN) -m db.cli init

db-migrate:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Running migrations..."
	$(VENV_DIR)/bin/alembic upgrade head

db-shell:
	@if [ -f scanner.db ]; then \
		sqlite3 scanner.db; \
	else \
		echo "Database not found. Run 'make db-init' first."; \
	fi

scan-demo:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Run 'make venv' first."; \
		exit 1; \
	fi
	@echo "Running demo scan..."
	$(PYTHON_BIN) cli_v2.py --dir tests/ --project demo --verbose --output report/demo_scan.json

clean-cache:
	@echo "Clearing cache..."
	rm -rf cache_data/
	@echo "Cache cleared."
