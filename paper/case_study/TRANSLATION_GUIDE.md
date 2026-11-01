# Independent translation guide (4 apps, about 45 minutes each)

> ⚠️ **Do not open `paper/case_study/README.md` or anything in `paper/case_study/apps/` until you have finished.** Those hold Claude's translations and results. The point of this exercise is that you translate *without* seeing them, so that we can measure how often two independent translators agree.

## What you are doing

Each app below builds an LLM prompt in Python, TypeScript or Rust. You read the few lines where it does that, and write the **same prompt** as a TrustLex program: every piece of outside text becomes an `input` with its source, and every message becomes a `system { }` or `instruction { }` block. Then you run the checker. That is all.

## Who does which app (swap if you like)

| App | Translator | Language |
|---|---|---|
| A. career-ops | Amritha | JavaScript |
| B. serviette | Lakshmi Shriyaa | Python |
| C. graphify | Karthick | Python |
| D. agent-browser | Karthick | Rust (short file) |

## The rules (same for everyone)

**1. Who wrote this text?** Decide for every piece of text that reaches the prompt:

| The text is… | Write |
|---|---|
| written by the app's developers (a string in the code, a prompt file in the repo) | a string literal, or `var x = "..."` |
| configuration the **person running their own copy** writes for themself (settings, their own profile or instructions file) | `var x = "..."` too: the attacker is not the operator |
| typed by an end user into the chat or a form | `input x` |
| a retrieved document, a web page, an uploaded or cloned file, a job ad, an email, a file name, a skill/plugin description: anything written by a third party | `input x from rag` |
| a tool or API result, **or text an LLM wrote** (a summary, a "memory", an extracted profile) | `input x from tool` |

**2. Where does it go?** A `system`/`developer` message, or a `system=` / `systemInstruction` parameter → `system { }`. A `user` message, or a `tool` message → `instruction { }`. Keep the order of the messages: several `system { }` and `instruction { }` blocks are allowed.

**3. Fixed choices.** If the app only ever accepts a value from a fixed set (a language code, a plan tier, an integer it computes), write a typed input: `input lang : enum("en", "fr")`, `input n : int`, `input id : pattern("[A-Z0-9]{8}")`.

**4. Escaping.** If the app itself escapes or wraps outside text before inserting it (for example in `<untrusted_...>` tags, or with `html.escape`), write `insert(sanitize(x))`. Otherwise write `insert(x)`. Do not add `sanitize` the app does not do.

**5. Loops and ifs.** TrustLex has neither. A loop over documents becomes **one** input (all documents together). For an `if`, translate the most common path and write one comment line saying what you left out.

**6. Long developer text** can be shortened to a placeholder: `"<the scoring rules from modes/oferta.md>"`. Only the *position* of outside text matters.

## Worked example (an app you are *not* translating)

Code (simplified):

```python
SYSTEM = "You are a helpful assistant. Use only the context."
chunks = search(question)                     # retrieved documents
messages = [
    {"role": "system", "content": SYSTEM + "\nContext:\n" + "\n".join(chunks)},
    {"role": "user",   "content": question},
]
```

Translation:

```
input chunks from rag      # retrieved documents: third-party text
input question             # typed by the user

system {
    "You are a helpful assistant. Use only the context."
    "Context:"
    insert(chunks)
}
instruction { insert(question) }
```

`python main.py check example.tlx` then reports `TL-S011`: retrieved text reaches the system prompt.

## The four apps: where to look

Open each link (pinned to the exact commit we analysed) and read only the listed lines.

**A. career-ops** (`career-ops-hq/career-ops`, commit `86979c5`)
- https://github.com/career-ops-hq/career-ops/blob/86979c50da59696cfef795933b9d35295796f0ba/openai-eval.mjs: lines 140-180 (where `jdText` comes from), 258-336 (the system prompt), 380-390 (the messages)
- https://github.com/career-ops-hq/career-ops/blob/86979c50da59696cfef795933b9d35295796f0ba/lib/context-budget.mjs: lines 240-330 and 365-390 (what `contextBody` contains)

**B. serviette** (`pathwaycom/serviette`, commit `e2a7a09`)
- https://github.com/pathwaycom/serviette/blob/e2a7a09bbc0b272a490aba26d850d363ec3ddf14/serviette/server/main.py: lines 395-440 (system prompt for the document-mode answer)
- https://github.com/pathwaycom/serviette/blob/e2a7a09bbc0b272a490aba26d850d363ec3ddf14/serviette/server/llm.py: lines 14-20, 51-55, 152-170 (the messages)
- https://github.com/pathwaycom/serviette/blob/e2a7a09bbc0b272a490aba26d850d363ec3ddf14/serviette/server/documents.py: lines 490-513 (`corpus_card`, `labeled`)

**C. graphify** (`Graphify-Labs/graphify`, branch `v8`, commit `32e5efe`)
- https://github.com/Graphify-Labs/graphify/blob/32e5efe935e6844ef39a5e33409e4efe848f2172/graphify/llm.py: lines 524-582 (system prompt), 615-700 (how files are read and wrapped), 2185-2195 and 1580-1595 (the messages)

**D. agent-browser** (`vercel-labs/agent-browser`, commit `5868f7c`)
- https://github.com/vercel-labs/agent-browser/blob/5868f7c05020e047c00e68e4abf9253cce864f41/cli/src/chat.rs: lines 105-180 (system prompt, user input, what happens when the conversation gets long) and 360-380 (browser results)

## What to hand in

1. Save each translation as `paper/case_study/independent/<app>.tlx` (for example `independent/career-ops.tlx`), starting with two comment lines: `# translator: <your name>` and `# time spent: <minutes>`.
2. Run `python main.py check paper/case_study/independent/<app>.tlx` and keep the output.
3. Tell Claude when all four are saved. Claude then compares your translations with its own (inputs, source tags, which block each insert goes to, sanitized or not, and the compiler verdict), reports the agreement, and you discuss every disagreement together. That agreement number goes into the paper.
