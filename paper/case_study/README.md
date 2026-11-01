# Real-app case study (E1)

Twelve open-source LLM applications, chosen by the pre-registered protocol in [SELECTION.md](SELECTION.md) (committed before any candidate was opened). [candidates.csv](candidates.csv) lists all 361 search results with the decision and reason for each. `apps/` holds the TrustLex translation of each app, with the repository commit, the exact files and line ranges of its prompt construction, the source of every input, and what TrustLex cannot express.

**Status:** draft translations by Claude are complete. The independent translations by the authors (4 apps, see [TRANSLATION_GUIDE.md](TRANSLATION_GUIDE.md)) and the agreement measurement are pending. Proofs of concept are pending.

## Results

| # | App | Stars | Verdict | Finding |
|---|---|---|---|---|
| S1-1 | paperclipai/paperclip | 109,823 | ✅ safe | comments go to the user turn inside hand-escaped `<turn>` tags |
| S1-2 | bytedance/deer-flow | 84,837 | ❌ TL-S013 ×2, TL-S012 | user-editable agent "soul" and third-party skill descriptions enter the **system prompt**, HTML-escaped (structure removed, instructions kept); the agent-name pattern `^[A-Za-z0-9-]+$` is unbounded |
| S1-3 | career-ops-hq/career-ops | 79,226 | ❌ TL-S011 | the **job description** (third-party text from a job board) is placed in the **system prompt**; a malicious posting can steer its own evaluation |
| S2-1 | pathwaycom/serviette | 58,736 | ✅ safe | retrieved chunks and question in the user turn; the system prompt holds only an integer document count |
| S2-2 | HKUDS/DeepTutor | 53,557 | ❌ TL-S011 ×2 | **memory written by an LLM from earlier conversations** and the names of uploaded sources enter the system prompt (persistent "memory poisoning" path) |
| S2-3 | Crosstalk-Solutions/project-nomad | 41,585 | ❌ TL-S011 | **retrieved knowledge-base chunks, including user-uploaded PDFs**, are sent as a `system`-role message |
| S3-1 | NousResearch/hermes-agent | 259,446 | ❌ TL-S011 ×2, TL-S013 | **project context files of a cloned repository** (AGENTS.md, .cursorrules) enter the system prompt, guarded only by a keyword threat scanner; agent-written memory and skill descriptions too |
| S3-2 | Graphify-Labs/graphify | 140,442 | ✅ safe | builds TrustLex's condition C by hand: `<untrusted_source>` tags, defanged control tokens, a system-prompt notice, files in the user turn |
| S3-3 | nexu-io/open-design | 105,321 | ❌ TL-S011 | "personal memory (auto-extracted from past chats)" enters the system prompt |
| S4-1 | vercel-labs/agent-browser | 45,121 | ❌ TL-S011 | **second-order injection**: web pages arrive as tool messages, but the LLM's summary of the conversation, web pages included, is re-inserted as a **`system` message** |
| S4-2 | tinyhumansai/openhuman | 42,476 | ❌ TL-S011 | names and descriptions of installed (possibly third-party) skills enter the system prompt **without escaping** |
| S5-1 | langchain-ai/chat-langchain | 6,470 | ✅ safe | static system prompt; LangChain's summarisation middleware returns the summary in a user message |

## Metrics

| Metric | Value |
|---|---|
| Apps with at least one leak | **8 of 12 (67%)** |
| Findings (errors) | 13: 9 × TL-S011 (retrieved / tool / LLM-written text in system), 3 × TL-S013 (sanitized free text in system), 1 × TL-S012 (unbounded validation pattern) |
| Sources behind the leaks | retrieved or third-party text 7 (documents, job ads, project files, skill descriptions), LLM-written memory or summaries 4, user-editable text 1, plus the pattern |
| False positives on the 4 safe apps | **0** |
| Lexical linter (B1) on the same translations | finds 9 of the 13; misses all 3 sanitized-in-system leaks; 1 false positive (serviette's integer count) |
| Inputs that could be refinement-typed | **2 of 31 (6%)**: real apps pass almost everything as free text, so typed fields (condition D) protect a small share of today's inputs |
| Features TrustLex cannot express | loops over documents, skills or tool calls (6 apps), optional prompt sections / conditionals (all 12), LLM calls whose output re-enters a prompt (summaries and memory, 6 apps) |

## Reading the results

- **The common leak is not raw user text.** None of the 12 apps puts the customer's own message in the system prompt. The leaks come from text the developers did not think of as "input": retrieved documents, job ads, project files, skill descriptions, and above all **text the app's own LLM wrote** (memory, summaries). This supports the paper's focus on indirect injection and on treating model output as untrusted.
- **Sanitizing is not a channel.** Three apps escape outside text and still place it in the system prompt; the escaping removes tags, not instructions. Fix A (TL-S013) is aimed at exactly this pattern.
- **Careful apps already do condition C by hand.** graphify and paperclip wrap outside text in tags and keep it in the user turn. TrustLex makes that layout the default and checks it at compile time.
- **Limits.** Translations are manual and model the main prompt path of each app; the many configuration conditionals were resolved to the most common path. TrustLex has no loops or branches, and cannot follow trust through a model call, which six apps rely on. Both are the two novelty options in the revision plan.
