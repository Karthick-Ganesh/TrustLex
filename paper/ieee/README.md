# TrustLex papers

Two versions share `refs.bib` and the result tables in `shared/`:

- `trustlex.tex`: IEEE conference paper (IEEEtran conference, target 7 pages).
- `trustlex_journal.tex`: extended journal version (IEEEtran journal, target 14-15 pages): longer
  introduction with research questions, a background section, full proofs, the checker algorithm,
  an IR example, a diagnostics table, case-study examples, a discussion section and fuller threats
  to validity.

Upload the whole folder (both `.tex` files, `refs.bib` and `shared/`) as one Overleaf project and
set the main document to the version you want.

## Compile on Overleaf (no install needed)

1. Overleaf → New Project → Upload Project → upload `trustlex.tex` and `refs.bib`
   (or a zip of this folder).
2. Menu → Compiler: **pdfLaTeX**. Overleaf ships `IEEEtran.cls` and `IEEEtran.bst`.
3. Recompile. Overleaf runs BibTeX automatically.

Locally (with TeX Live or MiKTeX): `latexmk -pdf trustlex.tex`.

## Before submitting

- Replace the placeholder authors, emails and guide in the `\author{...}` block.
- Values in red (`\pending{...}`) are interim: live runs still in progress or not yet re-judged.
  Find them with `grep -n "pending{" *.tex shared/*.tex`; the tables live once in `shared/`,
  so a value there is filled for both papers.
- Check the reference entries in `refs.bib` against Google Scholar or the
  publisher's page (some author lists are shortened to "and others").
- `../PAPER_CONTENT.md` is the longer version of the same content (extra
  tables, presentation notes for the review); this file is the condensed
  IEEE version.

## Compile locally (Tectonic)

Tectonic 0.17.0 is installed at `E:\TrustLex-local	ectonic` with its package cache on E:.
From `paper/ieee`, in Git Bash:

    export TECTONIC_CACHE_DIR='E:\TrustLex-local	ectonic-cache'
    /e/TrustLex-local/tectonic/tectonic.exe -X compile trustlex.tex --outdir build
    /e/TrustLex-local/tectonic/tectonic.exe -X compile trustlex_journal.tex --outdir build

Last check: conference 7 pages, journal 14 pages, no overfull lines. Tectonic uses XeTeX;
Overleaf's pdfLaTeX can break lines slightly differently, so recheck the page count there.
