PAPER := main

.PHONY: all macros clean

all: macros
	# -g forces a rebuild: the generated table bodies are read with the TeX
	# primitive, which latexmk does not track as a dependency.
	latexmk -pdf -g -interaction=nonstopmode $(PAPER).tex

macros: ## regenerate LaTeX numbers from research/results/*.json
	python3 ../experiments/make_macros.py

clean:
	latexmk -C
	rm -rf generated
