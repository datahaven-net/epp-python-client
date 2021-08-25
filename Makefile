PYTHON_VERSION=python3.8
PIP:="venv/bin/pip3"
REQUIREMENTS_TXT:=requirements.txt

.PHONY: clean pyclean

pyclean:
	@find . -name *.pyc -delete

clean: pyclean
	@rm -rf venv

venv:
	@rm -rf venv
	@$(PYTHON_VERSION) -m venv venv
	@$(PIP) install --upgrade pip
	@$(PIP) install -r $(REQUIREMENTS_TXT)

.PHONY: test
test: venv
	PYTHONPATH=./src ./venv/bin/pytest -vv --color=yes --capture=no --log-cli-level=DEBUG ./tests

rabbitmq_server_dev:
	@echo "Starting RabbitMQ server, admin dashboard is available here: http://127.0.0.1:15672"
	@rabbitmq-server
