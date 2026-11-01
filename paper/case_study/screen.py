"""First screening pass over the pre-registered search results.

Rows are kept in search order (stars, descending). A row is excluded here
only for a reason that the name, licence or description states plainly
(a list, a course, a framework or library, no licence, a fork, too few
stars); everything else is left for manual review, and the manual decision
is added to candidates.csv by hand with its reason.

    python paper/case_study/screen.py   ->  paper/case_study/candidates.csv
"""
import csv
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = [  # (pattern on name + description, exclusion reason)
    (r"\bawesome\b|curated|\blist of\b|collection of|\bhand-picked\b|\bresources\b|cheat ?sheet",
     "a list or collection, not an application"),
    (r"\bcourse\b|tutorial|lessons|curriculum|roadmap|\bfor beginners\b|from scratch|\blearn\b|\bguide\b|cookbook",
     "a course or tutorial"),
    (r"\bframework\b|\blibrary\b|\bsdk\b|toolkit|\bengine\b|\bapi layer\b|\bgateway\b|observability|\bevals?\b",
     "a framework, library or infrastructure, not an end-user application"),
    (r"\bmodel series\b|language model series|pretrained|fine-?tun|\btraining\b|inference server|serving",
     "a model or model-serving repository"),
    (r"\bmcp server", "an MCP server collection or tool server, not an application"),
    (r"system_prompts?_leaks|prompt(s)? (library|collection)", "a prompt collection, not an application"),
]


def screen(row: dict) -> str:
    if row["license"] in ("none", "NOASSERTION"):
        return "no OSI licence stated (criterion 1)"
    if row["fork"] == "true":
        return "fork"
    if int(row["stars"]) < 100:
        return "fewer than 100 stars"
    text = f"{row['repo']} {row['description']}".lower()
    for pattern, reason in RULES:
        if re.search(pattern, text):
            return reason
    return ""


def main():
    fields = ["repo", "stars", "license", "language", "fork", "pushed", "description"]
    out, seen = [], set()
    for stratum in ("S1", "S2", "S3", "S4"):
        with (HERE / "search" / f"{stratum}.tsv").open(encoding="utf-8") as f:
            for rank, line in enumerate(f, 1):
                row = dict(zip(fields, line.rstrip("\n").split("\t")))
                duplicate = row["repo"] in seen
                seen.add(row["repo"])
                reason = "already listed under an earlier stratum" if duplicate else screen(row)
                out.append({"stratum": stratum, "rank": rank, **row,
                            "decision": "exclude" if reason else "review", "reason": reason})
    with (HERE / "candidates.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(out[0]))
        writer.writeheader()
        writer.writerows(out)
    for stratum in ("S1", "S2", "S3", "S4"):
        review = [r for r in out if r["stratum"] == stratum and r["decision"] == "review"]
        print(f"\n== {stratum}: {len(review)} left for manual review")
        for r in review:
            print(f"  {r['rank']:>3} {r['repo']:<42} {r['stars']:>6} {r['language']:<11} {r['description'][:70]}")


if __name__ == "__main__":
    main()
