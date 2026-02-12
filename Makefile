.PHONY: install test sample

install:
	pip install -U pip
	pip install -r requirements.txt
	pip install -e .

test:
	python -m pytest -q

sample:
	alen-audit report --input examples/findings.sample.json --outdir out --project "Audit SI - Internal" --owner "Alen"
