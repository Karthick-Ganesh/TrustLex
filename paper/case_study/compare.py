"""Agreement between Claude's translations (apps/) and the authors'
independent translations (independent/).

Two translators name inputs differently, so programs are compared by what
the security analysis sees, in three separate dimensions:

  placement   for every block, which kinds of text enter it and how:
              (block, outside/validated, raw/sanitized/declassified),
              ignoring which trust tag the outside text carries
  tags        the same, with the trust tag (user/rag/tool/typed) included
  finding     whether outside text reaches a system block (the leak), and
              the exact error codes

    python paper/case_study/compare.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from semantic import analyze  # noqa: E402

LEAK_CODES = {"TL-S010", "TL-S011", "TL-S013", "TL-S014"}


def profile(path: Path):
    checked = analyze(path.read_text(encoding="utf-8"), path.name)
    sources = {}
    for name, sym in checked.symbols.items():
        if sym.kind == "input":
            sources[name] = "typed" if sym.input_type is not None else (sym.source_tag or "user")
    tagged = set()
    for block in checked.blocks:
        for s in block.template().slots:
            how = "declassified" if s.declassified is not None else "sanitized" if s.sanitized else "raw"
            tagged.add((block.kind.value, sources.get(s.input, "?"), how))
    placement = {(b, "validated" if tag == "typed" else "outside", how) for b, tag, how in tagged}
    codes = sorted({d.code for d in checked.diagnostics.errors})
    other = sorted(set(codes) - LEAK_CODES - {"TL-S012"})
    return {"placement": placement, "tags": tagged, "codes": codes,
            "leak": bool(set(codes) & LEAK_CODES), "other_errors": other}


def jaccard(a: set, b: set) -> tuple[int, int]:
    return len(a & b), len(a | b)


def main():
    pairs = []
    for mine in sorted((HERE / "independent").glob("*.tlx")):
        key = mine.stem.lower()
        match = [p for p in (HERE / "apps").glob("*.tlx") if p.stem.lower().split("_", 1)[-1] == key]
        if not match:
            print(f"{mine.name}: no Claude translation named *_{key}.tlx")
            continue
        pairs.append((match[0], mine))
    if not pairs:
        print("no independent translations yet")
        return
    totals = {"placement": [0, 0], "tags": [0, 0]}
    leak_agree = codes_agree = 0
    for claude, author in pairs:
        a, b = profile(claude), profile(author)
        print(f"\n== {author.stem}")
        if b["other_errors"]:
            print(f"   note: the author's file has other errors {b['other_errors']} (fix them first)")
        for dim in ("placement", "tags"):
            o, u = jaccard(a[dim], b[dim])
            totals[dim][0] += o
            totals[dim][1] += u
            print(f"   {dim:9} agreement {o}/{u}")
            for item in sorted(a[dim] - b[dim]):
                print(f"     only Claude: {item}")
            for item in sorted(b[dim] - a[dim]):
                print(f"     only author: {item}")
        leak_agree += a["leak"] == b["leak"]
        codes_agree += a["codes"] == b["codes"]
        print(f"   finding   Claude {'LEAK' if a['leak'] else 'safe'} {a['codes'] or ''}   "
              f"author {'LEAK' if b['leak'] else 'safe'} {b['codes'] or ''}")
    n = len(pairs)
    print(f"\nover {n} app(s): leak verdict {leak_agree}/{n}, exact codes {codes_agree}/{n}, "
          + ", ".join(f"{d} {o}/{u} = {o / max(u, 1):.0%}" for d, (o, u) in totals.items()))


if __name__ == "__main__":
    main()
