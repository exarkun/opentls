SHELL := /bin/bash

deps:
	pip install -r requirements/development.txt \
	            -r requirements/production.txt

lint:
	flake8 --exit-zero tls/*py

dist:
	python setup.py sdist

site:
	cd docs; make html

test:
	coverage run setup.py test

unittest:
	coverage run -m unittest

coverage:
	coverage report --include="tls*"

clean:
	find . -type f -name "*.pyc" -exec rm '{}' +
	find . -type d -name "__pycache__" -exec rmdir '{}' +
	rm -rf *.egg-info .coverage
	cd docs; make clean

docs: site
