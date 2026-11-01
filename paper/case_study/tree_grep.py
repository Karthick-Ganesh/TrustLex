"""List the files of a GitHub repository whose path matches a pattern
(default: prompt-related names), using one tree request per repository.

    python paper/case_study/tree_grep.py owner/name [pattern]
"""
import json
import re
import subprocess
import sys

repo = sys.argv[1]
pattern = re.compile(sys.argv[2] if len(sys.argv) > 2 else r"prompt|system|chat|agent|rag|qa|llm", re.I)
meta = json.loads(subprocess.run(["gh", "api", f"repos/{repo}"], capture_output=True, text=True,
                                 encoding="utf-8").stdout)
tree = json.loads(subprocess.run(["gh", "api", f"repos/{repo}/git/trees/{meta['default_branch']}?recursive=1"],
                                 capture_output=True, text=True, encoding="utf-8").stdout)
code = (".py", ".ts", ".js", ".mjs", ".tsx", ".go", ".md", ".txt", ".jinja", ".j2", ".yaml", ".yml", ".json")
paths = [t["path"] for t in tree.get("tree", []) if t["type"] == "blob" and t["path"].endswith(code)
         and pattern.search(t["path"]) and "test" not in t["path"].lower() and "/docs/" not in t["path"]]
print(f"{repo} @ {meta['default_branch']} ({len(paths)} matching files)")
for p in paths[:60]:
    print("  ", p)
