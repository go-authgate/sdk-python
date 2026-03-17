.PHONY: test lint fmt typecheck install clean

install:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --tb=short

coverage:
	python -m coverage run -m pytest tests/ -v --tb=short
	python -m coverage report -m

lint:
	python -m ruff check src/ tests/

fmt:
	python -m ruff format src/ tests/
	python -m ruff check --fix src/ tests/

typecheck:
	python -m mypy src/authgate/

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov/
