"""Locate prompt construction in a GitHub repository without cloning it.

Lists the code files whose path or contents suggest prompt assembly
(GitHub code search for chat-message construction), so that a reviewer can
open them and judge criteria 3, 4 and 6 of SELECTION.md.

    python paper/case_study/inspect_repo.py owner/name [owner/name ...]
"""
import json
import subprocess
import sys
import time

QUERIES = [
    '"role" "system" repo:{repo}',
    'system_prompt repo:{repo}',
    'SystemMessage repo:{repo}',
]


def gh(*args):
    out = subprocess.run(["gh", "api", *args], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        return None, out.stderr.strip()[:200]
    return json.loads(out.stdout), ""


def main():
    for repo in sys.argv[1:]:
        meta, err = gh(f"repos/{repo}")
        if meta is None:
            print(f"== {repo}: {err}")
            continue
        print(f"== {repo}  ({meta['default_branch']}, {meta['size'] // 1024} MB, {meta.get('language')})")
        files = {}
        for q in QUERIES:
            data, err = gh("-X", "GET", "search/code", "-f", f"q={q.format(repo=repo)}", "-f", "per_page=15")
            time.sleep(7)  # code search allows 10 requests a minute
            if data is None:
                print(f"   search failed: {err}")
                continue
            for item in data.get("items", []):
                files.setdefault(item["path"], set()).add(q.split()[0])
        for path in sorted(files)[:25]:
            print(f"   {path}   [{', '.join(sorted(files[path]))}]")
        if not files:
            print("   (no prompt-construction files found by code search)")


if __name__ == "__main__":
    main()
