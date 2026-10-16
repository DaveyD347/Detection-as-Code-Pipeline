.PHONY: install lint test replay convert coverage all

install:
	pip install -c requirements.lock -e '.[dev]'

lint:
	ruff check src tests && ruff format --check src tests
	dac lint

test:
	pytest

replay:
	dac replay

convert:
	dac convert

coverage: replay
	dac coverage

all: lint test replay convert coverage
