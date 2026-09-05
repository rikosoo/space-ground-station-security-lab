PAPER := main

.PHONY: all macros clean

all: macros
	latexmk -pdf -interaction=nonstopmode $(PAPER).tex

macros: ## regenerate LaTeX numbers from research/results/*.json
	python3 ../experiments/make_macros.py

clean:
	latexmk -C
	rm -rf generated
