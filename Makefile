.PHONY: mypy black flake8 all

all: mypy black flake8 test
	@echo done

mypy:
	mypy --version
	mypy cda.py

black:
	black --version
	black --check --diff .

flake8:
	flake8 --version
	flake8

test:
	pytest --version
	pytest

