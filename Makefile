.PHONY: install test eval run sandbox
install:
	pip install -r requirements.txt
test:
	python -m pytest -q
eval:
	python -m eval --llm mock --runs 2
run:
	python -m agent.cli run --scenario $(or $(S),s2) --auto-approve
sandbox:
	uvicorn sandbox.app:app --port 8001 --reload
