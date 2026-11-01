"""Agreement between Claude's translations (apps/) and the authors'
independent translations (independent/).

Two translators name inputs differently, so programs are compared by what
the security analysis sees: for every block, the multiset of
(block kind, source of the input, how it was inserted) of the slots it
contains, plus the compiler verdict (the set of error codes).

    python paper/case_study/compare.py
"""
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from semantic import analyze  # noqa: E402


def profile(path: Path):
    checked = analyze(path.read_text(encoding="utf-8"), path.name)
    if not checked.blocks and not checked.ok:
        return None, sorted({d.code for d in checked.diagnostics.errors})
    sources = {name: sym.source_tag or ("typed" if sym.input_type else "user")
               for name, sym in checked.symbols.items() if sym.kind == "input"}
    for name, sym in checked.symbols.items():
        if sym.kind == "input" and sym.input_type is not None:
            sources[name] = "typed"
    slots = Counter()
    for block in checked.blocks:
        for s in block.template().slots:
            how = "declassified" if s.declassified is not None else "sanitized" if s.sanitized else "raw"
            slots[(block.kind.value, sources.get(s.input, "?"), how)] += 1
    codes = sorted({d.code for d in checked.diagnostics.errors})
    return slots, codes


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
    agree_verdict = total_overlap = total_union = 0
    for claude, author in pairs:
        a_slots, a_codes = profile(claude)
        b_slots, b_codes = profile(author)
        same_verdict = a_codes == b_codes
        agree_verdict += same_verdict
        a_set, b_set = set(a_slots or ()), set(b_slots or ())
        overlap, union = len(a_set & b_set), len(a_set | b_set)
        total_overlap += overlap
        total_union += union
        print(f"\n== {author.stem}")
        print(f"   verdict   Claude {a_codes or ['ok']}   author {b_codes or ['ok']}   {'AGREE' if same_verdict else 'DIFFER'}")
        print(f"   placement agreement {overlap}/{union} (block, source, insertion) kinds")
        for item in sorted(a_set - b_set):
            print(f"     only Claude: {item}")
        for item in sorted(b_set - a_set):
            print(f"     only author: {item}")
    print(f"\nverdict agreement: {agree_verdict}/{len(pairs)} apps; "
          f"placement agreement (Jaccard): {total_overlap}/{total_union} = {total_overlap / max(total_union, 1):.0%}")


if __name__ == "__main__":
    main()
