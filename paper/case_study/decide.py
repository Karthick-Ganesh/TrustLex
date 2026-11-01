"""Apply the manual screening decisions to candidates.csv.

Rows that screen.py left for review are decided here, in search order, until
each stratum is full; later rows are marked "not reached". Every decision
carries its reason (see SELECTION.md for the criteria)."""
import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
QUOTA = {"S1": 3, "S2": 3, "S3": 3, "S4": 2}
DECISIONS = {  # repo -> (decision, reason)
    "paperclipai/paperclip": ("include", "app; developer-written board-chat system prompt; user and agent comments as input"),
    "bytedance/deer-flow": ("include", "app; developer-written lead-agent prompt; soul, skills, memory, user messages as input"),
    "career-ops-hq/career-ops": ("include", "app; developer-written evaluator prompt; job description as input"),
    "ollama/ollama": ("exclude", "a model runtime, not an application that builds prompts (criterion 2)"),
    "pathwaycom/serviette": ("include", "app; developer-written grounded-answer prompt; retrieved chunks and question as input"),
    "vectorize-io/hindsight": ("exclude", "agent-memory infrastructure, not an end-user application (criterion 2)"),
    "HKUDS/DeepTutor": ("include", "app; developer-written tutor prompt; memory, sources, knowledge base, question as input"),
    "Crosstalk-Solutions/project-nomad": ("include", "app; developer-written chat prompt; knowledge-base chunks and chat as input"),
    "affaan-m/ECC": ("exclude", "a bundle of skills and settings for coding agents; builds no prompts of its own (criterion 3)"),
    "NousResearch/hermes-agent": ("include", "app; developer-written agent prompt; context files, memory, skills, task as input"),
    "msitarzewski/agency-agents": ("exclude", "a collection of agent prompt files, not an application (criterion 2)"),
    "langflow-ai/langflow": ("exclude", "a low-code builder: its users write the system prompts (criterion 3)"),
    "farion1231/cc-switch": ("exclude", "a configuration switcher for coding CLIs; builds no prompts (criterion 3)"),
    "langchain-ai/langchain": ("exclude", "a framework (criterion 2); its official templates are stratum S5"),
    "Graphify-Labs/graphify": ("include", "app; developer-written extraction prompt; repository files as input"),
    "nexu-io/open-design": ("include", "app; developer-written designer prompt; memory and brief as input"),
    "shanraisshan/claude-code-best-practice": ("exclude", "documentation, not an application (criterion 2)"),
    "vercel-labs/agent-browser": ("include", "app (chat mode); developer-written prompt; web pages, summary, instruction as input"),
    "tinyhumansai/openhuman": ("include", "app; developer-written channel prompt; skills and channel messages as input"),
}


def main():
    path = HERE / "candidates.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    included = {s: 0 for s in QUOTA}
    for row in rows:
        stratum = row["stratum"]
        if row["decision"] != "review":
            continue
        if included[stratum] >= QUOTA[stratum]:
            row["decision"], row["reason"] = "not reached", "stratum already full"
            continue
        if row["repo"] not in DECISIONS:
            raise SystemExit(f"no decision recorded for {row['repo']} ({stratum} rank {row['rank']})")
        row["decision"], row["reason"] = DECISIONS[row["repo"]]
        included[stratum] += row["decision"] == "include"
    rows.append({"stratum": "S5", "rank": "1", "repo": "langchain-ai/chat-langchain", "stars": "6470",
                 "license": "MIT", "language": "TypeScript", "fork": "false", "pushed": "2026-11-01",
                 "description": "official LangChain docs chat (search/S5.tsv)", "decision": "include",
                 "reason": "highest-starred official template application of langchain-ai and run-llama"})
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    counts = {}
    for row in rows:
        counts[row["decision"]] = counts.get(row["decision"], 0) + 1
    print(counts, included)


if __name__ == "__main__":
    main()
