# Real-app case study: selection protocol

Written on 2026-11-01, **before** any candidate app was examined or translated. The rules below decide which apps enter the study. Every candidate considered is listed in `candidates.csv` with the reason it was kept or excluded, so the selection can be audited.

## Population

Open-source LLM-integrated applications on GitHub that build prompts for a chat-completion API (OpenAI, Anthropic, Gemini, or a compatible API, called directly or through LangChain, LlamaIndex or a similar library).

## Inclusion criteria (all must hold)

1. **Public repository** with an OSI-approved licence.
2. **An application, not a library.** It serves end users: a bot, assistant, agent, web app or CLI tool. Frameworks themselves are excluded; their official example templates form their own stratum (below).
3. **A developer-written system prompt** (a `system` or `developer` message, or an equivalent `system=`/`systemInstruction` parameter).
4. **At least one outside input** reaches the prompt: an end-user message, a retrieved document, a web page, a file, an email, or a tool/API result.
5. **Popularity and activity:** at least 100 GitHub stars, and a commit in the 24 months before 2026-11-01.
6. **Readable prompt construction:** the code that assembles the messages can be located by reading the repository, without running it.

## Exclusion criteria

- Forks and near-duplicates of an app already included (same prompt code).
- Courses, notebooks and tutorials whose only purpose is teaching.
- Apps whose prompts are built at run time from a remote prompt-management service, so the prompt is not in the repository.
- Repositories with no licence.

## Strata (12 apps)

> **Amendment, 2026-11-02, before any candidate was screened:** the study was reduced from 20 to 12 apps (and the independent translations from 6 to 4) to fit the submission deadline. The strata keep their proportions. The search results in `search/` had been downloaded, but no candidate had been opened or judged when this change was made.

| Stratum | Apps | Typical outside input |
|---|---|---|
| S1 Customer-facing chat / support bots | 3 | user message |
| S2 Retrieval-augmented Q&A over documents | 3 | retrieved chunks |
| S3 Agents and tool-using assistants | 3 | tool / API / web results |
| S4 Email, summarisation and other text-processing apps | 2 | emails, web pages, files |
| S5 Official framework templates (LangChain, LlamaIndex) | 1 | retrieved chunks, user message |

## Search procedure (fixed in advance)

For each stratum, the GitHub repository search below is run once, sorted by stars (descending). Candidates are examined in that order; the first ones that meet every criterion are included until the stratum is full. A query may be repeated with the next page if a stratum is not full after its first page.

| Stratum | Query |
|---|---|
| S1 | `chatbot openai system prompt in:readme,description stars:>=100 pushed:>=2024-11-01` |
| S2 | `rag chat with documents in:readme,description stars:>=100 pushed:>=2024-11-01` |
| S3 | `llm agent tools in:readme,description stars:>=100 pushed:>=2024-11-01` |
| S4 | `gpt email summarizer in:readme,description stars:>=100 pushed:>=2024-11-01` |
| S5 | official example/template applications in the `langchain-ai` and `run-llama` organisations |

## What is recorded per app

- repository, commit hash, licence, stars, stratum;
- the file(s) and line ranges where prompts are assembled;
- every input and its source tag (`user`, `rag`, `tool`), and whether its values could be refinement-typed;
- the TrustLex translation (`apps/<name>.tlx`), with the commit it was translated from;
- the compiler verdict, each finding, and the manual confirmation (true / false positive);
- features TrustLex could not express (loops over documents, conditionals, functions);
- the keyword-filter and lexical-linter baselines on the same translation.

## Independence

Claude (the AI assistant) drafts each translation. At least one author independently translates a sample of at least 4 of the 12 apps from the original source code, without seeing the draft, and agreement between the two translations is reported. Disagreements are resolved by discussion and recorded.

> **Deviation, 2026-11-02, reported in the paper:** only 2 of the 4 planned independent translations (career-ops, graphify) were done, for lack of time; agreement is reported over these two. The author saw the comparison for career-ops before translating graphify, and received the same file and line pointers to the prompt code that the translation guide lists. After translation, Claude escaped literal braces in the graphify prompt text (a syntax error, TL-L005); nothing else was changed.

## Ethics

Only public code is read. Proofs of concept run only on local copies, with the authors' own API keys, never against deployed services. Confirmed leaks in maintained projects are reported to the maintainers by the authors (Karthick Ganesh drafts and sends the reports).
