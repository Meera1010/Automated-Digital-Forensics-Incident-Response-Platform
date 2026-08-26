.PHONY: run test install build

run:
	python run.py

test:
	pytest tests/

install:
	pip install -r requirements.txt

build:
	docker build -t adfir-platform .
