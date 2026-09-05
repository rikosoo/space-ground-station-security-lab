# Paper

**A Cloud-Native Security Architecture for Detecting Cyber Threats in Satellite
Ground Segments**

## Build

```bash
make            # regenerates numbers, then builds main.pdf
make macros     # numbers only
```

`make macros` runs `../experiments/make_macros.py`, which reads
`research/results/*.json` and writes LaTeX macro definitions and table bodies
into `generated/`. **No number in this paper is typed by hand**, so re-running
the experiments and rebuilding cannot leave a stale figure in the text. If
`generated/` is missing, the document still compiles with `??` placeholders and
prints a warning.

Requires `latexmk` and a TeX distribution with `booktabs`, `siunitx`, `balance`
and `hyperref`.

## Structure

| File | Section |
|---|---|
| `sections/01-introduction.tex` | Motivation, research question, contributions |
| `sections/02-background.tex` | CCSDS/SDLS, SPARTA, prior empirical work |
| `sections/03-threat-model.tex` | Assets, adversary capability levels N1–N3, assumptions |
| `sections/04-architecture.tex` | Layers, the two detection paths, event schema |
| `sections/05-detection.tex` | Rule taxonomy, R06 and R07 in detail, portability |
| `sections/06-methodology.tex` | Protocol, benign workload, scoring definitions |
| `sections/07-results.tex` | RQ1–RQ5 |
| `sections/08-discussion.tex` | Findings and practitioner implications |
| `sections/09-limitations.tex` | Threats to validity |
| `sections/10-conclusion.tex` | Conclusion, future work, availability |

## Reproducing the results

```bash
python ../experiments/run_experiment.py all --trials 10
make
```

Deterministic under a fixed seed; a test in `tests/test_lab.py` asserts it.
