# BULL III paper

`paper.md` is the editable manuscript. `evidence.json` supplies the plotted
operator-reported counts. `make_figures.py` produces the three vector diagrams
and a 300 dpi chart, then Pandoc renders the PDF:

```bash
python3 docs/papers/bull-iii/make_figures.py
pandoc docs/papers/bull-iii/paper.md --from markdown+raw_tex \
  --pdf-engine=pdflatex -V geometry:margin=0.8in -V fontsize=10pt \
  -V colorlinks=true -V urlcolor=MidnightBlue \
  --resource-path=docs/papers/bull-iii \
  -o output/pdf/BULL-III-20260927.pdf
```

The paper deliberately does not bundle or publish private KVM evidence. The
source revision in the evidence ledger is the tested runtime revision, while
the paper's own commit is a documentation revision.
