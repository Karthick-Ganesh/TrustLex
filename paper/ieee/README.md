# TrustLex IEEE conference paper

`trustlex.tex` (IEEEtran, two-column conference format) and `refs.bib`.

## Compile on Overleaf (no install needed)

1. Overleaf → New Project → Upload Project → upload `trustlex.tex` and `refs.bib`
   (or a zip of this folder).
2. Menu → Compiler: **pdfLaTeX**. Overleaf ships `IEEEtran.cls` and `IEEEtran.bst`.
3. Recompile. Overleaf runs BibTeX automatically.

Locally (with TeX Live or MiKTeX): `latexmk -pdf trustlex.tex`.

## Before submitting

- Replace the placeholder authors, emails and guide in the `\author{...}` block.
- Cells in red (`\pending{...}`) are waiting on the last live runs; they are
  filled in when the runs finish.
- Check the reference entries in `refs.bib` against Google Scholar or the
  publisher's page (some author lists are shortened to "and others").
- `../PAPER_CONTENT.md` is the longer version of the same content (extra
  tables, presentation notes for the review); this file is the condensed
  IEEE version.
