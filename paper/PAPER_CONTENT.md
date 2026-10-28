# TrustLex — paper content (draft, format-neutral)

> Working content for the paper, to be pasted into the format your guide gives.
> Numbers marked **⟦UPDATE⟧** change when the runs started on 2026-10-28 finish
> (extra repeat + Tensor Trust benchmark). Everything else is final for the
> code at commit `5ed3ea2`.
>
> Suggested length if the format is a standard 8–10 page conference paper:
> §1 1 p, §2 1 p, §3–4 2 p, §5 1 p, §6 0.5 p, §7 2.5 p, §8–10 1.5 p.

---

## Authors (title page)

- Amritha Varshini Pakanati (24BCE0390), amritha.varshini2024@vitstudent.ac.in
- V L Lakshmi Shriyaa (24BCE0778), lakshmishriyaa.vl2024@vitstudent.ac.in
- Karthick Ganesh (24BCI0018), karthick.ganesh2024@vitstudent.ac.in
- Dr. Krishnaraj N, Assistant Professor Sr. Grade 2, Department of Database Systems, krishnaraj.n@vit.ac.in

School of Computer Science and Engineering (SCOPE), Vellore Institute of Technology, Vellore, Tamil Nadu 632014, India.
Code: https://github.com/Karthick-Ganesh/TrustLex

## Title (options)

1. **TrustLex: Compile-Time Trust Typing for Injection-Safe Prompts in LLM-Integrated Applications**
2. TrustLex: Prepared Statements for Prompts — A Security-Typed Compiler Against Prompt Injection
3. Trust as a Type: A Compiler Front-End That Rejects Prompt-Injection-Prone Prompts Before They Exist

**Keywords:** prompt injection, LLM-integrated applications, information-flow control, security type systems, domain-specific languages, compiler construction, taint analysis, non-interference.

---

## Abstract

Companies increasingly deploy large language models (LLMs) not as stand-alone chatbots but inside their own applications: a support bot on a website, a retrieval-augmented assistant over internal documents, an agent that reads tool and API results. Each such application builds a prompt by concatenating the developer's trusted instructions (the system prompt) with untrusted text — customer messages, retrieved documents, tool outputs. Because the model receives one undifferentiated string, untrusted text can impersonate the developer: this is prompt injection, ranked the top risk for LLM applications by OWASP.

We present **TrustLex**, a domain-specific language and compiler that makes trust a grammar-level type. Every input declares its origin (`user`, `rag`, `tool`); the compiler tracks trust through variables, interpolation, concatenation and reassignment by exact symbolic evaluation over a five-level trust lattice, and **refuses to compile** any prompt in which untrusted data can reach the privileged system channel without passing through a sanitizer, unless the input carries a refinement type (`enum`, `pattern`, `int`) that provably cannot express an instruction. We prove non-interference up to sanitization and validation, and show the check is also complete for the language. Accepted programs compile to a checksummed, optionally HMAC-sealed IR that is bound at run time into OpenAI or Anthropic API payloads.

On a labelled corpus of 48 programs TrustLex achieves an F1 of 1.00, against 0.55 for a lexical linter and 0.80 for a keyword filter that also flags 30% of benign inputs. Across 1,536 program–attack pairs, naive templating lets structural injection reach the system prompt in 38.1% of cases; TrustLex in 0%. In live experiments with three hosted models, using our own attacks and the public Tensor Trust benchmark, typed inputs block 100% of attacks before any API call, and TrustLex's layout significantly lowers indirect-injection success — e.g. from 75.0% to 56.2% on allam-2-7b with Tensor Trust attacks (exact McNemar p = 0.017) and from 28.1% to 6.2% on gpt-oss-20b with ours (p = 0.016). Compilation takes about 5 ms for a typical program.

---

## 1. Introduction

### 1.1 Where LLMs are actually used

Most real-world use of LLMs today is not a person chatting with ChatGPT. It is an **LLM-integrated application**: a company calls a general-purpose model (GPT, Gemini, Claude, Llama) through an API and wraps it in its own logic:

- a **customer-support bot** on a telecom, bank or e-commerce website;
- a **retrieval-augmented (RAG) assistant** that answers from the company's help-center articles or internal documents;
- an **email or document assistant** that summarizes messages written by outsiders;
- an **agent** that calls tools and web APIs and feeds their results back to the model;
- an **internal enterprise copilot** with confidential business rules in its system prompt.

The model itself is not custom; the *application* is. What makes each application specific is its **system prompt** — the developer's instructions, persona, business rules and restrictions — plus the outside text it pulls in at run time.

### 1.2 The problem: one string, many authors

Every such application builds its prompt by *gluing strings together*: developer instructions + the customer's message + a retrieved document + a tool result. The model receives a single sequence of tokens and has no reliable way to tell **who wrote which part**. An attacker who controls any of the outside text can therefore write text that *looks like* developer instructions:

- **Direct prompt injection** — the customer types "Ignore all previous instructions and …" [Perez & Ribeiro 2022].
- **Indirect prompt injection** — the attacker plants the instruction in a web page, document, email or API response that the application later retrieves [Greshake et al. 2023].

OWASP lists prompt injection as risk LLM01 — the top risk — for LLM applications [OWASP 2025].

### 1.3 The analogy: SQL injection and prepared statements

This is the same class of bug as **SQL injection**. In the early web, applications built SQL queries by concatenating user input into query strings, so input could become code. The fix that worked was not better input filters but a change of *construction*: **prepared statements**, where the query structure is fixed by the developer and user input can only fill typed slots, never change the structure.

> **TrustLex is prepared statements for prompts, checked by a compiler.**
> Untrusted text can fill a slot, but the compiler guarantees it can never become part of the developer's instructions.

Like a type checker that refuses to compile `int x = "hello"`, TrustLex refuses to compile a prompt in which a customer's message flows into the system prompt unsanitized — and it shows the exact path the data took and a verified fix.

### 1.4 Why a compiler

Existing defences act at two other points:

- **at the model** — training or prompting the model to separate instructions from data (instruction hierarchy, StruQ, spotlighting); these reduce but do not eliminate attacks and depend on the model;
- **at run time** — classifiers and guardrails that inspect every request (Lakera Guard, PromptShield, NeMo Guardrails); these add latency and cost per request and give no guarantee.

Neither gives the *developer* a guarantee about the prompt they wrote. TrustLex acts **at build time, before the prompt exists**: a non-compliant prompt is never built, and no flow analysis runs per request. It is complementary to both other layers — the compiled prompt can still be sent to a hardened model, and a detector can be plugged in as the sanitizer.

### 1.5 Contributions

1. **A prompt DSL with trust as a grammar-level type.** Inputs declare their origin (`input msg`, `input doc from rag`, `input r from tool`); privileged (`system`) and unprivileged (`instruction`) channels are syntactic blocks; `sanitize()` is an explicit, visible declassification point; refinement types (`enum`, `pattern`, `int`) mark inputs that cannot carry instructions.
2. **An exact, flow-sensitive security analysis** by symbolic evaluation over a five-level trust lattice, with a **non-interference theorem** (sound) and a **completeness** result (no false positives) for the language, both validated by property-based testing on random programs.
3. **A safety analysis for regular-expression types** that decides whether a `pattern` can match free text (whitespace, invisible characters, unbounded repetition, over 64 characters).
4. **An end-to-end chain of custody**: a canonical IR with a SHA-256 integrity checksum and optional HMAC seal, invariant re-checks at generation and at binding, a registry of named sanitizers, and provider-correct OpenAI/Anthropic API payloads in which values remain JSON data.
5. **Developer-facing diagnostics** in compiler style: taint paths as source snippets, machine-applicable fix-its that are re-checked, and a semantics-preserving prompt optimizer.
6. **An evaluation** combining offline detection and leakage experiments, live attack-success experiments with three hosted models in direct and indirect (RAG) scenarios, a public benchmark (Tensor Trust), and a complexity analysis.

---

## 2. Background and threat model

### 2.1 Who is trusted

| Party | Writes | Trusted? |
|---|---|---|
| Application developer | the TrustLex program: system prompt, rules, layout | **Yes** |
| End user / customer | messages typed into the application | No (`UNTRUSTED`) |
| Retrieval system | documents, web pages, knowledge-base articles | Partly (`SEMI_TRUSTED`): the store may contain attacker-planted text |
| Tools and external APIs | tool results, API responses | Partly (`SEMI_TRUSTED`) |

### 2.2 Attacker

The attacker controls the content of one or more inputs: the customer message (direct injection) or a document / tool result that the application retrieves (indirect injection). The attacker knows the language, the compiler and the default sanitizer (no security by obscurity). The attacker **cannot** modify the TrustLex program, the compiler, or — when the HMAC seal is used — the compiled IR between build and deployment.

### 2.3 Security goal

**Untrusted text must never be able to act as developer instructions.** Formally (§4.4): the rendered system prompt may depend on an untrusted input only through the sanitizer, or through choosing a value from a validated type's fixed, instruction-free language.

### 2.4 Where TrustLex applies — and API calls

TrustLex targets exactly the setting of §1.1: **an application that sends a developer-written system prompt plus outside text to a model API.** It protects the API call at three points:

1. **Building the API request.** The compiler's output *is* the API request body (OpenAI Chat Completions or Anthropic Messages). Input values enter the payload as JSON string data, never by string splicing, so a value such as `"}]}, {"role": "system", "content": "…"` stays inside its own content field and cannot forge a new message or role (*JSON-structure injection*). The role of every message (system/developer vs. user) is fixed by the program, not by the data.
2. **Data that comes back from other APIs.** Responses from external APIs and tools are declared as `input result from tool` and tracked as `SEMI_TRUSTED`; they cannot reach the system prompt unsanitized (`TL-S011`). This covers indirect injection through API responses, web search results and retrieved documents.
3. **The deployed prompt artifact.** The compiled IR carries an integrity checksum and, with a deployment key, an HMAC-SHA256 seal; `bind()` refuses a tampered, re-labelled or unsealed IR and re-checks the security invariant before every API call. A prompt that passed review cannot be silently weakened between build and production.

**Out of scope** (stated explicitly to avoid over-claiming):
- persuasion *inside the user turn*: TrustLex keeps untrusted text out of the privileged channel and spotlights it in the user turn, but it does not make the model immune to being talked into something;
- *which tools the model decides to call* with what arguments (agent control flow) — this is the domain of runtime systems such as CaMeL, with which TrustLex composes;
- training-time attacks, model weights, jailbreaks of the base model unrelated to injected data.

### 2.5 Running example

An Acme Telecom support bot with retrieval:

```
var rules = "You are Ava, the support assistant of Acme Telecom. Only discuss Acme products, plans, orders and billing."
input msg                                   # customer message: UNTRUSTED
input article from rag                      # help-center article: SEMI_TRUSTED
input order_id : pattern("[A-Z0-9]{8}")     # validated: cannot carry a sentence
input topic : enum("billing", "outage", "upgrade", "cancellation", "general")

system {
    insert(rules)
    "Order: {order_id}. Topic: {topic}."
}
instruction {
    "Help-center article:" insert(sanitize(article))
    "Customer message:"   insert(sanitize(msg))
}
```

Moving `insert(article)` into the `system` block — a layout common in RAG tutorials — is rejected with `TL-S011`; inserting `msg` there is rejected with `TL-S010`. In our live experiment (§7.4) this rejected layout is the most attacked one on gpt-oss-20b and gemma-4 for every attack set and scenario.

*(Figure 1 suggestion: three boxes on the left — Developer (green, trusted), Customer and Documents/APIs (red/orange, untrusted) — flowing into the TrustLex compiler in the middle, which outputs either a checked API payload (system channel: developer text + sanitized/validated slots only; user channel: spotlighted data) or a compile error with the taint path.)*

---

## 3. The TrustLex language

### 3.1 Declarations

```
var persona = "You are a support bot."     # developer text: TRUSTED
input user_msg                             # end-user text: UNTRUSTED
input doc from rag                         # retrieved document: SEMI_TRUSTED
input result from tool                     # tool / API output: SEMI_TRUSTED
input lang : enum("en", "fr", "ta")        # validated
input order_id : pattern("[A-Z0-9]{8}")    # validated
input qty : int(1, 100)                    # validated
persona = persona + " Be brief."           # reassignment (inputs are read-only)
```

Unknown source tags fail closed (`from web` is treated as `UNTRUSTED`).

### 3.2 Blocks and expressions

`system { … }` is the privileged system prompt; `instruction { … }` is the user turn. A block contains string literals and `insert(expr)` items. Expressions are string literals (with `{name}` interpolation and `"""…"""` multi-line strings), names, concatenation `a + b`, `sanitize(e)` and parentheses. There are no branches, loops or calls: programs are **straight-line**, which is what makes an exact analysis possible.

### 3.3 Grammar (LALR(1), no conflicts)

```
program    : stmt*
stmt       : var_decl | input_decl | assign | block | ";"
var_decl   : "var" IDENT "=" expr
input_decl : "input" IDENT ("from" IDENT)? (":" type_spec)?
type_spec  : IDENT | IDENT "(" ")" | IDENT "(" type_arg ("," type_arg)* ")"
type_arg   : STRING | NUMBER | IDENT
assign     : IDENT "=" expr
block      : ("system" | "instruction") "{" item* "}"
item       : STRING | "insert" "(" expr ")" | ";"
expr       : expr "+" term | term
term       : STRING | IDENT | "sanitize" "(" expr ")" | "(" expr ")"
```

### 3.4 The one rule

> **Data from an `input` may enter a `system` block only through `sanitize()`, unless the input is validated** — however it gets there: directly, through `{interpolation}`, or through any chain of variables and reassignments.

| Data | in `system` | in `instruction` |
|---|---|---|
| string literals; variables holding only literals | ✅ | ✅ |
| `sanitize(…)` of anything | ✅ | ✅ |
| `input x` (user) | ❌ `TL-S010` | ✅ (spotlighted) |
| `input x from rag` / `from tool` | ❌ `TL-S011` | ✅ (spotlighted) |
| `input x : enum/pattern/int` (validated) | ✅ (value checked at bind, `TL-G006`) | ✅ |

---

## 4. Security type system

### 4.1 Trust lattice

```
TRUSTED  ⊑  VALIDATED  ⊑  SANITIZED  ⊑  SEMI_TRUSTED  ⊑  UNTRUSTED
```

Ordered by taint (higher = less trustworthy); the join ⊔ is the less trusted of two levels.

| Construct | Label |
|---|---|
| string literal | `TRUSTED` |
| `input x : τ` (any source) | `VALIDATED` |
| `input x` / `from user` | `UNTRUSTED` |
| `input x from rag` / `from tool` | `SEMI_TRUSTED` |
| `a + b`, `"…{a}…"` | `label(a) ⊔ label(b)` |
| `sanitize(e)` | every external part of `e` lowered to `SANITIZED` |

`SANITIZED` keeps sanitized outside data distinguishable from developer text, so code generation knows which slots must pass through the runtime sanitizer. `VALIDATED` sits below it: a validated value needs no sanitizer because its type restricts it to a fixed language checked at bind time.

**Clearances.** Content may enter a block only if its label ⊑ the block's clearance: `system` = `SANITIZED`, `instruction` = `UNTRUSTED` (anything). A `relaxed` policy downgrades `TL-S011` to a warning.

### 4.2 Exact flow-sensitive evaluation

Instead of approximating, the checker evaluates the program symbolically. The value of each variable at each program point is a **template**: literal text interleaved with input **slots**; each slot records whether it was sanitized and the path by which it arrived.

```
input user_msg                           Γ(user_msg) = [Slot(user_msg)]
var note = "Customer said: {user_msg}"   Γ(note) = [Text("Customer said: "), Slot(user_msg)]
note = note + " Please help."            Γ(note) = [Text(…), Slot(user_msg), Text(" Please help.")]
note = "Always answer in English."       Γ(note) = [Text("Always answer in English.")]   ← strong update
system { insert(note) }                  label = TRUSTED ✓
```

- **Strong updates**: an overwritten variable is clean again (a flow-insensitive analysis would reject this program — a false positive).
- **Position matters**: each block sees variable values at its own position.
- **Partial sanitization is caught**: `sanitize(u) + u` still contains a raw slot.

### 4.3 Validated inputs and pattern safety

A `pattern` counts as validating only if it **cannot match free text**. The pattern is parsed with Python's own regex parser and its syntax tree is walked; it is rejected (`TL-S012`) if it can match whitespace or invisible characters, uses `.` or a negated class (`[^…]`, `\S`, `\W`, `\D`), has an unbounded repeat (`*`, `+`, `{n,}`), uses backreferences or lookarounds, or can match more than 64 characters. Empty enums and enum entries over 64 characters are also rejected. A value of an accepted type can *select an option*; it cannot spell out an instruction sentence. `bind()` checks every value against its type and additionally refuses role markers and delimiter tags in pattern-typed values.

### 4.4 Non-interference theorem

> **Theorem (non-interference up to sanitization and validation).** Let *P* be a TrustLex program with no `TL-S010`/`TL-S011`/`TL-S012` errors under the strict policy, and *san* the runtime sanitizer. Let σ₁, σ₂ assign strings to *P*'s inputs such that both bind (σᵢ(y) ∈ L(τ) for every validated input *y* : τ). If *san*(σ₁(x)) = *san*(σ₂(x)) for every free-text input *x*, and σ₁(y) = σ₂(y) for every validated input *y*, then every `system` block of *P* renders to the same text under σ₁ and σ₂.

In words: **raw outside text can influence the privileged prompt only through `sanitize()` or by choosing among a validated type's fixed values.**

*Proof sketch.*
1. **Exactness.** By induction over the statements of *P*, the template Γ(v) bound to each variable at each program point denotes *v*'s runtime value. Base cases: literals and inputs. Concatenation, interpolation and `sanitize` are homomorphic over rendering. Assignment is a strong update, exact because *P* has no control flow.
2. **Clean templates.** If label(t) ⊑ `SANITIZED`, every slot of *t* is sanitized or validated (a raw free-text slot has level ≥ `SEMI_TRUSTED`). Hence render(t, σ) depends on σ only through *san* ∘ σ on free-text inputs and σ on validated inputs, which agree by assumption.
3. **Block check.** The checker requires label(t) ⊑ `SANITIZED` for every `system` item; by (1) that template is the item's runtime content, by (2) it renders equally under σ₁ and σ₂. ∎

**Completeness.** Because the evaluation is exact, a program is rejected *only if* some raw slot reaches a `system` block, and then there exist σ₁, σ₂ as above that render it differently. The check has **no false positives** for this language.

**Preservation downstream.** IR slots come directly from the checked templates; `generate()`, `from_json()` and `bind()` re-verify the invariant, re-deriving each input's trust from its source tag or recorded type rather than trusting stored labels. The optimizer only rewrites developer text and keeps the slot sequence.

**Mechanised validation.** The theorem is tested with `hypothesis` on random programs (including typed inputs): every accepted program renders identical system text under two assignments that differ in raw content but sanitize identically (soundness); every rejected program renders differently (completeness); the same holds through IR serialisation and every optimizer level. In a 500-program sample, 398 were accepted and 102 rejected. A second property test checks that every string matched by an accepted pattern is at most 64 printable, whitespace-free characters.

---

## 5. Compiler implementation

TrustLex is implemented in about 4,100 lines of Python 3.10+ with PLY 3.11 (LALR(1)), with a 1,700-line evaluation harness and 492 automated tests. The pipeline follows the classic compiler phases:

| Phase | Module | Input → output | Key techniques |
|---|---|---|---|
| 1. Lexical analysis | `lexer.py` | text → tokens | PLY tokenizer; exact line/column spans; **trust seeded per token**; strings pre-split into text and `{holes}`; raw lexing of `pattern(...)` arguments; error recovery (`TL-L001`–`L006`) |
| 2. Syntax analysis | `parser_ast.py` | tokens → typed AST | LALR(1) grammar, zero conflicts (tested); error productions with targeted hints (`TL-P003`–`P009`); **exact "expected" sets** computed by simulating pending reductions (LALR state merging otherwise over-reports); panic-mode recovery |
| 3. Semantic / security analysis | `semantic.py` | AST → checked program | name resolution with "did you mean"; trust lattice; exact symbolic evaluation; regex safety analysis; taint paths; machine-applicable fix-its that are re-checked |
| 4. Intermediate code generation | `codegen.py` | checked program → IR | text parts and input slots kept separate (no placeholder strings); canonical JSON; SHA-256 checksum + optional HMAC seal; self-verification of the invariant |
| 5. Code optimization | `optimizer.py` | IR → smaller IR | rule-based rewriting of developer text only, to a fixpoint; correctness criterion = whitespace equivalence with the slot sequence preserved; property-tested (idempotent, never grows, keeps invariant) |
| 6. Target code generation / binding | `codegen.py` | IR + values → API payload | registry of named sanitizers; bind-time type checks; OpenAI / Anthropic payload mapping |
| Driver | `main.py` | CLI | `compile`, `check` (trust trace), `fix`, `demo`, interactive REPL, `--stages` timings |

**Diagnostics.** All phases report into one diagnostic bag in source order, in a rustc-like format with primary and secondary spans:

```
error[TL-S010]: UNTRUSTED data from input `user_msg` reaches a `system` block
 --> prompt.tlx:5:12
  |
5 |     insert(user_msg)
  |            ^~~~~~~~ raw input inserted here
 ::: prompt.tlx:1:7
1 | input user_msg
  |       -------- `user_msg` is UNTRUSTED input
  = help: sanitize the value before it enters the block: `insert(sanitize(user_msg))`
```

**Runtime sanitizer** `trustlex-default/1` (pluggable by name): NFKC normalization; removal of control, zero-width and bidi-override characters; defusing of chat-template role markers (`<|im_start|>`, `[INST]`, `<<SYS>>`, `Human:`/`Assistant:` turns); a length cap; and **spotlighting** [Hines et al. 2024] inside `<untrusted_input name=… source=…>` delimiters that the value cannot close early (break-outs are matched on the NFKC form, so fullwidth look-alikes are defused too).

**Optimizer.** At `-O1`, `examples/safe.tlx` shrinks from 153 to 140 characters (−8%), the first demo scenario from 133 to 116 (−13%); untrusted content is never touched because at compile time it exists only as slots.

---

## 6. Complexity analysis

Let *n* be the program size in tokens, *S* the largest template built during analysis (in parts), and *m* the size of the generated IR.

| Phase | Time | Reason |
|---|---|---|
| Lexing | O(n) | one pass of a regular-expression tokenizer |
| Parsing | O(n) | LALR(1): each token is shifted once, each reduction is O(1); the exact expected-set computation runs only on syntax errors |
| Name resolution | O(n) expected | hash-table symbol lookups |
| Security analysis | O(n · S) | each statement builds a template by copying at most S parts; labels are joins over a constant-height (5-level) lattice |
| Pattern safety | O(\|p\|) per pattern | one walk of the regex syntax tree, with maximum-match-length computed bottom-up |
| Code generation | O(m) | one pass over the checked templates; checksum/HMAC are linear in the IR |
| Optimization | O(k · m), k = number of fixpoint rounds | each rule is a linear string rewrite; every rewrite (except one-time newline/tab normalisation) strictly shortens the text, so k ≤ m |
| Binding (per request) | O(m + Σ\|values\|) | sanitizer steps and type checks are linear in input length |

**Typical programs.** For programs that do not repeatedly duplicate a value, S is bounded by the program's own text and the whole pipeline is near-linear. Measured (median of 5 runs, AMD Ryzen laptop, Windows 11, Python 3.10.5; one-time 16 ms parser-table construction excluded):

| statements | 10 | 50 | 100 | 500 | 1,000 | 2,000 | 5,000 |
|---|---|---|---|---|---|---|---|
| total ms | 4.7 | 20.3 | 44.0 | 206.8 | 520.1 | 1,205.2 | 3,765.2 |
| ms / statement | 0.47 | 0.41 | 0.44 | 0.41 | 0.52 | 0.60 | 0.75 |

A log–log fit over sizes ≥ 100 gives time ∝ n^1.14. Lexing and parsing take 63–80% of the time; the security analysis itself takes 14–31%. The example application compiles in about 5 ms, so compilation adds no noticeable cost to a build, and **no flow analysis runs per request**.

**Worst case.** Because templates are copied, a program that repeatedly doubles a value — `a = a + a` repeated k times — builds a template of 2^k parts:

| k (doubling statements) | 10 | 12 | 14 | 16 | 17 |
|---|---|---|---|---|---|
| slots in the system prompt | 1,024 | 4,096 | 16,384 | 65,536 | 131,072 |
| compile time (ms) | 18.8 | 72.6 | 305.4 | 1,321.3 | 2,686.6 |

Time doubles with each statement, exactly tracking the template size. Two observations make this acceptable in practice: (i) the cost is **proportional to the prompt being built** — a program that inserts the value produces an output of 2^k slots, so any compiler that emits the prompt explicitly must pay this; and (ii) such a prompt is far beyond any model's context window (k = 17 with a one-word value already exceeds 100k tokens). Two standard remedies would bound the analysis independently of output size: **hash-consing** templates into a DAG (sharing instead of copying, making the analysis O(n) in the number of statements), or a **size cap** that rejects any template above the largest context window with a compile error. We leave the DAG representation as future work.

---

## 7. Evaluation

We answer five research questions:
- **RQ1** Does TrustLex detect unsafe prompt programs more accurately than lightweight alternatives?
- **RQ2** Does it prevent structural injection from reaching the system prompt?
- **RQ3** How does it change attack success against real models, for direct and indirect injection?
- **RQ4** Does the result hold on a public, independently written attack set?
- **RQ5** What does it cost (utility, compile time)?

### 7.1 Setup

- **Corpus**: 48 hand-written TrustLex programs (26 unsafe, 22 safe) in 14 categories (direct insert, interpolation, multi-hop variable chains, partial sanitization, re-assignment after sanitization, RAG/tool in system, look-alike literals, realistic applications, …).
- **Attacks**: 32 attack strings in 8 categories (direct override, role tokens, nested role tokens, transcript forgery, delimiter escape, Unicode obfuscation, payload splitting, social engineering); 10 benign inputs with expected keywords.
- **Baselines**: **B1** a lexical linter (flags `insert(input)` patterns textually); **B2** a runtime keyword blocklist applied to the naively rendered prompt; a **naive renderer** (plain string concatenation, `sanitize` = identity) representing typical hand-built prompts.
- **Live models** (free API tiers, 2026-10-28, temperature 0, max 1,024 output tokens): `openai/gpt-oss-20b` (Groq), `allam-2-7b` (Groq), `gemma-4-26b-a4b-it` (Google Gemini API). Each trial embeds a fresh random **canary** (e.g. `TLX-7F3A9C`) in the attack; **success** = the reply contains the canary in a sentence that is not a refusal (replies that merely quote it while refusing are counted separately). Reasoning ("thought") parts are excluded. Responses are cached so every number is reproducible from the logs.
- **Statistics**: 95% Wilson intervals for rates; **exact McNemar tests** for paired comparisons (same attack under two conditions).

### 7.2 RQ1 — Detection

| Method | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **TrustLex** | 26 | 0 | 0 | 22 | **1.00** | **1.00** | **1.00** |
| B1 lexical linter | 13 | 8 | 13 | 14 | 0.62 | 0.50 | 0.55 |
| B2 keyword filter | 26 | 13 | 0 | 9 | 0.67 | 1.00 | 0.80 |

B1 misses every leak that travels through variables, interpolation or re-assignment (13 of 26) and flags correctly sanitized programs. B2 catches all leaks only because it sees the raw naive rendering, at the cost of flagging 13 of 22 safe programs. A perfect TrustLex score is expected (the analysis is exact for this language); the comparison shows *where* lightweight approaches fail.

### 7.3 RQ2 — Structural leakage (1,536 program × attack pairs)

| Condition | Canary reaches system | Raw attack text in system | **Structural leak** |
|---|---|---|---|
| Naive rendering | 81.2% | 81.2% | **38.1%** |
| TrustLex | 20.8% | 9.1% | **0.0%** |

A *structural leak* is a chat-template role token, a forged transcript turn, or a delimiter break-out reaching the system message. With TrustLex, 832 pairs are blocked at compile time, 96 at bind time (value fails its type) and 608 are rendered — none with surviving structure. The remaining "canary reaches system" cases are sanitized, spotlighted data, by design. All 32 attacks pass the default sanitizer with their structure removed; the 17 with no structural payload (pure natural language) pass through as spotlighted text — which is why §7.4 measures model behaviour. The keyword filter B2 catches only 56.2% of the naive pairs in which an attack reaches the system message, while flagging 30% of benign inputs.

### 7.4 RQ3 — Live attack success rate

**Conditions.** Direct: **A** customer message raw in the system prompt; **B** raw in the user turn; **C** the TrustLex program (sanitized + spotlighted in the user turn); **D** C plus typed fields into which the attacker also writes. Indirect (RAG; the customer question is harmless, the attacker controls a retrieved article): **A** article raw in the system prompt (TrustLex rejects this program with `TL-S011`); **B** raw in the user turn; **C** TrustLex (sanitized + spotlighted).

Attack success rate with our 32 attacks (n = attack trials per condition; 2 repeats where n = 64; gpt-oss-20b has 1 repeat because of its daily token limit):

| Model | Scenario | n | A naive, system | B naive, user | C TrustLex | D TrustLex typed |
|---|---|---|---|---|---|---|
| gpt-oss-20b | direct | 32 | 25.0% | 12.5% | 9.4% | **0%** (all blocked) |
| gpt-oss-20b | indirect | 32 | 28.1% | 18.8% | **6.2%** | — |
| allam-2-7b | direct | 64 | 48.4% | 42.2% | 48.4% | **0%** |
| allam-2-7b | indirect | 64 | 57.8% | 59.4% | **40.6%** | — |
| gemma-4-26b-a4b-it | direct | 64 | 4.7% | 1.6% | 0.0% | **0%** |
| gemma-4-26b-a4b-it | indirect | 64 | 6.2% | 0.0% | 0.0% | — |

Paired comparisons (exact McNemar test, same attack and repeat under two conditions; "a/b" = trials where only the first / only the second condition was attacked successfully):

| Model | Attacks | Scenario | A vs C | p | B vs C | p |
|---|---|---|---|---|---|---|
| gpt-oss-20b | ours | direct | 8/3 | 0.227 | 3/2 | 1.000 |
| gpt-oss-20b | ours | indirect | 7/0 | **0.016** | 4/0 | 0.125 |
| gpt-oss-20b | Tensor Trust | direct | 12/9 | 0.664 | 6/6 | 1.000 |
| gpt-oss-20b | Tensor Trust (32) | indirect | 8/4 | 0.388 | 2/4 | 0.688 |
| allam-2-7b | ours | direct | 9/9 | 1.000 | 11/15 | 0.557 |
| allam-2-7b | ours | indirect | 18/7 | **0.043** | 19/7 | **0.029** |
| allam-2-7b | Tensor Trust | direct | 7/5 | 0.774 | 13/6 | 0.167 |
| allam-2-7b | Tensor Trust | indirect | 17/5 | **0.017** | 14/3 | **0.013** |
| gemma-4 | ours | direct | 3/0 | 0.250 | 1/0 | 1.000 |
| gemma-4 | ours | indirect | 4/0 | 0.125 | 0/0 | 1.000 |
| gemma-4 | Tensor Trust | direct | 0/0 | 1.000 | 0/0 | 1.000 |
| gemma-4 | Tensor Trust | indirect | 2/0 | 0.500 | 0/0 | 1.000 |

Utility on benign inputs stayed at 80–100% in every condition; a TrustLex condition was never more than one request below a naive one.

**Findings.**
1. **Typed inputs block every attack, on every model, before any API call.** D's 0% holds by construction — it demonstrates that a refinement-typed field cannot carry an injection, independent of the model; the free-text message in D is protected exactly as in C. (There is no D in the indirect scenario because a free-text article cannot be given a refinement type.)
2. **The layout TrustLex rejects is the most attacked one on the stronger models.** Condition A (untrusted text in the system prompt) has the highest success rate for gpt-oss-20b and gemma-4 in every attack set and scenario — empirical support for `TL-S010`/`TL-S011`. On allam-2-7b, A and B are similar: the model does not distinguish the channels at all.
3. **TrustLex significantly reduces indirect injection.** With the attack in a retrieved document, C is significantly lower than both naive layouts on allam-2-7b for both attack sets (A vs C p = 0.043 and 0.017; B vs C p = 0.029 and 0.013), and lower than the system-prompt layout on gpt-oss-20b with our attacks (28.1% → 6.2%, p = 0.016). With Tensor Trust attacks on gpt-oss-20b, C (31.2%) is below A (43.8%) but not significantly, and not below B (25.0%).
4. **No significant effect for direct injection.** In the direct scenario no difference between A, B and C is significant on any model: spotlighting marks the customer's message as data, but that message is addressed to the model anyway. Only the typed fields (D) help there. This matches the literature: prompt-level defences reduce but do not eliminate injection, and their effect depends on the model and the attack [Hines et al. 2024; Chen et al. 2025]. allam-2-7b, a 7B model without instruction-hierarchy training, also often repeats codes it finds anywhere in its context.
5. **A strongly aligned model resists all conditions.** gemma-4 is near 0% everywhere, so the conditions cannot be separated; its single direct success (A14) is borderline (it acknowledged the code).

*(Figure: grouped bar charts `asr.png` and `asr_indirect.png` with 95% Wilson intervals.)*

### 7.5 RQ4 — Public benchmark (Tensor Trust)

To avoid relying only on our own attacks, we use the **Tensor Trust** hijacking benchmark [Toyer et al. 2024], a public set of 776 prompt-injection attacks written by human players of an online game whose goal is to make a model say "Access Granted". We keep only the attack text (not the game's defence prompts), select the 206 distinct attacks that name the target phrase literally and are at most 800 characters, replace the phrase with our per-trial canary so the same judge applies, and draw a seeded random sample of 64. The attacks were run in both scenarios under the same conditions and models.

| Model | Scenario | n | A | B | C | D |
|---|---|---|---|---|---|---|
| gpt-oss-20b | direct | 64 | 23.4% | 18.8% | 18.8% | **0%** |
| gpt-oss-20b | indirect | 32 ⟦UPDATE: 64⟧ | 43.8% | 25.0% | 31.2% | — |
| allam-2-7b | direct | 64 | 62.5% | 70.3% | 59.4% | **0%** |
| allam-2-7b | indirect | 64 | 75.0% | 73.0% | **56.2%** | — |
| gemma-4-26b-a4b-it | direct | 64 | 1.6% | 1.6% | 1.6% | **0%** |
| gemma-4-26b-a4b-it | indirect | 64 | 4.7% | 1.6% | 1.6% | — |

The public attacks are stronger than ours (on allam-2-7b 56–75% vs. 41–59%), yet typed inputs still block all of them, and the indirect-scenario reduction on allam-2-7b is the strongest effect in the study (p = 0.017 and 0.013, table above).

### 7.6 RQ5 — Cost

- **Utility**: 80–100% of benign requests answered usefully in all conditions; TrustLex conditions were never lower than the naive ones by more than one request.
- **Compile time**: ~5 ms for the example application; near-linear scaling (§6).
- **Run-time cost**: binding runs only the sanitizer and type checks, linear in input size — no classifier call, no extra LLM call, no per-request flow analysis.

---

## 8. Related work

| Dimension | DSPy & LMQL | CaMeL | TaintP2X & DeepClause | Semantic Kernel templates | PromptShield, Lakera Guard, NeMo Guardrails | **TrustLex** |
|---|---|---|---|---|---|---|
| Domain | LM pipelines / constrained decoding | privileged/quarantined LLM split with capabilities | taint tracking in application code | prompt templating in an SDK | run-time detection and filtering | **purpose-built prompt DSL** |
| Reasons about trust | No | Yes | Yes | Yes (variables unsafe by default) | implicitly / rules | **Yes, deterministically** |
| Enforcement point | — | run time (custom interpreter) | static analysis of general code | render time | run time, after assembly | **compile time, before assembly** |
| Flow analysis | — | run-time data flow | approximate | No | No | **exact, flow-sensitive** |
| Trust as a grammar-level type | No | No | No | No (opt-out flag) | No | **Yes** |
| Guarantee | — | policy over tracked flows | detection | inserted values cannot create message tags | none (best effort) | **non-interference; sound and complete** |
| Remediation | — | deny action | report | — | block / flag | **verified fix-its** |
| Per-request overhead | inference | extra LLM + interpreter | none (dev time) | encoding | classifier call | **none beyond linear sanitizer** |

**Prompt programming languages.** DSPy [Khattab et al. 2024] and LMQL [Beurer-Kellner et al. 2023] treat prompts as programs but optimize *what* the model does; they do not model where text comes from.

**CaMeL** [Debenedetti et al. 2025] separates a privileged planner LLM from a quarantined LLM that reads untrusted data, and enforces capability policies on tool calls at run time. It targets agent actions; TrustLex targets prompt *construction*, one step earlier. They compose: a TrustLex program can be the trusted prompt source of a CaMeL-style system.

**Static taint analysis for LLM applications.** TaintP2X [He et al. 2026] and DeepClause [Andreas 2026] retrofit taint tracking onto general-purpose code and must approximate control flow, aliasing and libraries. TrustLex designs the language so the analysis is exact.

**Run-time detectors and guardrails** (PromptShield [Jacob et al. 2024], Lakera Guard, NeMo Guardrails [Rebedea et al. 2023]) are probabilistic, add per-request cost and give no guarantee; our keyword baseline B2 illustrates the false-positive problem. They are orthogonal: a detector can be registered as a named TrustLex sanitizer.

**Auto-sanitizing templates.** CSAS [Samuel et al. 2011] showed for web templates that a compiler can infer contexts and insert sanitizers using type qualifiers. Semantic Kernel [Microsoft 2024] encodes all prompt-template variables at render time. TrustLex brings CSAS-style compile-time, flow-sensitive typing to prompts.

**Model-level defences.** StruQ [Chen et al. 2025], the instruction hierarchy [Wallace et al. 2024] and spotlighting [Hines et al. 2024] train or prompt the model to separate instructions from data. TrustLex supplies the structural separation these defences assume; our allam-2-7b results show why that structure matters when the model is not trained to use it.

**Benchmarks.** Tensor Trust [Toyer et al. 2024] and the formal benchmark of Liu et al. [2024] evaluate attacks and defences at the model level; we use Tensor Trust attacks as an independent attack set.

**Information-flow control foundations.** Denning's lattice model [1976], non-interference [Goguen & Meseguer 1982], security type systems [Volpano et al. 1996; Sabelfeld & Myers 2003], flow-sensitive typing [Hunt & Sands 2006]; `sanitize()` is an explicit declassification point [Sabelfeld & Sands 2009].

**The gap TrustLex fills:** grammar-native trust typing; compile-time enforcement with no per-request analysis; an exact analysis that is sound *and* complete; compiler-style remediation; an end-to-end chain of custody from source to API payload.

---

## 9. Limitations and threats to validity

**Limitations of the approach**
- **The guarantee covers the privileged channel.** Untrusted text is still allowed (spotlighted) in the user turn, where a model can still be persuaded; TrustLex guarantees untrusted text cannot pose as developer instructions, not that the model is immune to persuasion.
- **`sanitize()` is only as strong as the sanitizer.** The default removes structural vectors but cannot neutralize natural-language instructions in general; the sanitizer is pluggable for that reason.
- **Validation is syntactic.** A permissive pattern such as `[A-Za-z]{1,40}` admits a single word like `Ignoreallinstructions`; prefer `enum` or the tightest pattern.
- **Completeness relies on straight-line programs.** Adding branches or loops would require joining templates at merge points: still sound, no longer complete.
- **Exponential worst case** for repeated self-duplication (§6), bounded by remedies we describe.
- **Agent tool calls are out of scope** (§2.4).

**Threats to validity**
- **Hand-written corpus and attacks** — mitigated by the Tensor Trust benchmark (§7.5).
- **Few models, free tiers.** Three models; hosted free models change or are retired; exact IDs and dates are recorded and all responses cached.
- **Sample size.** 32–64 attack trials per condition give wide intervals; 5 of the 24 paired comparisons are significant, all in the indirect scenario. Repeats at temperature 0 vary only the canary and are correlated.
- **Empty replies.** About 4–5 of 64 gpt-oss-20b replies per condition were empty because its reasoning used up the 1,024-token output budget; they count as unsuccessful attacks.
- **Canary-based success is a proxy**: attacks that change behaviour without repeating the canary are not counted; a refusal-aware judge prevents counting refusals that quote the canary.
- **Benchmark adaptation**: Tensor Trust attacks were written against the game's defences, not our application; attacks that spell the target phrase indirectly are excluded.
- **Condition D is a guarantee check, not a behavioural measurement.**

---

## 10. Conclusion and future work

Prompt injection in LLM-integrated applications is, at its root, a construction bug: trusted instructions and untrusted data are glued into one string. TrustLex addresses it the way programming languages addressed SQL injection and cross-site scripting — by making the trust of every piece of text part of the program's type and refusing to build an unsafe prompt. Its analysis is exact for its language, yielding a non-interference guarantee with no false positives, and its compiled output carries that guarantee to the API call. The live experiments show the two layers working together: compile-time types and channel separation give model-independent protection, and spotlighting adds a model-dependent reduction on models trained to respect it.

**Future work:** hash-consed (DAG) templates for linear worst-case analysis; conditionals and loops with sound joins; trust tracking through *model outputs* and multi-step agent pipelines (output of one call as `input from tool` of the next); integration with capability-based runtimes such as CaMeL for tool-call policies; learned or classifier-backed sanitizers registered by name; IDE integration (language server) for live diagnostics.

---

## References

- Andreas. *Static Taint Analysis for LLM Agents.* DeepClause (blog), 2026.
- Beurer-Kellner, L., Fischer, M., Vechev, M. *Prompting Is Programming: A Query Language for Large Language Models.* PLDI 2023.
- Chen, S., Piet, J., Sitawarin, C., Wagner, D. *StruQ: Defending Against Prompt Injection with Structured Queries.* USENIX Security 2025.
- Debenedetti, E., et al. *Defeating Prompt Injections by Design* (CaMeL). arXiv:2503.18813, 2025.
- Denning, D. E. *A Lattice Model of Secure Information Flow.* CACM 19(5), 1976.
- Goguen, J. A., Meseguer, J. *Security Policies and Security Models.* IEEE S&P 1982.
- Greshake, K., et al. *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* AISec 2023.
- He, J., et al. *TaintP2X: Detecting Taint-Style Prompt-to-Anything Injection Vulnerabilities in LLM-Integrated Applications.* ICSE 2026.
- Hines, K., et al. *Defending Against Indirect Prompt Injection Attacks With Spotlighting.* arXiv:2403.14720, 2024.
- Hunt, S., Sands, D. *On Flow-Sensitive Security Types.* POPL 2006.
- Jacob, D., et al. *PromptShield: Deployable Detection for Prompt Injection Attacks.* CODASPY 2024.
- Khattab, O., et al. *DSPy: Compiling Declarative Language Model Calls into Self-Improving Pipelines.* ICLR 2024.
- Lakera. *Lakera Guard.* Commercial service.
- Liu, Y., et al. *Formalizing and Benchmarking Prompt Injection Attacks and Defenses.* USENIX Security 2024.
- McNemar, Q. *Note on the Sampling Error of the Difference Between Correlated Proportions or Percentages.* Psychometrika 12(2), 1947.
- Microsoft. *Protecting against Prompt Injection Attacks in Chat Prompts.* Semantic Kernel blog, 2024.
- OWASP. *OWASP Top 10 for Large Language Model Applications* (LLM01: Prompt Injection), 2025.
- Perez, F., Ribeiro, I. *Ignore Previous Prompt: Attack Techniques for Language Models.* NeurIPS ML Safety Workshop 2022.
- Rebedea, T., et al. *NeMo Guardrails.* EMNLP 2023 (Demos).
- Sabelfeld, A., Myers, A. C. *Language-Based Information-Flow Security.* IEEE JSAC 21(1), 2003.
- Sabelfeld, A., Sands, D. *Declassification: Dimensions and Principles.* JCS 17(5), 2009.
- Samuel, M., Saxena, P., Song, D. *Context-Sensitive Auto-Sanitization in Web Templating Languages Using Type Qualifiers.* CCS 2011.
- Toyer, S., et al. *Tensor Trust: Interpretable Prompt Injection Attacks from an Online Game.* ICLR 2024.
- Volpano, D., Smith, G., Irvine, C. *A Sound Type System for Secure Flow Analysis.* JCS 4(2–3), 1996.
- Wallace, E., et al. *The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions.* arXiv:2404.13208, 2024.
- Wilson, E. B. *Probable Inference, the Law of Succession, and Statistical Inference.* JASA 22(158), 1927.

---

## Appendix — figures and tables to prepare

| # | Content | Source |
|---|---|---|
| Fig. 1 | Trust flow overview (developer / customer / documents → compiler → payload or error) | draw (§2.5 description) |
| Fig. 2 | Compiler pipeline (6 phases, compile time vs. run time) | README §3 diagram |
| Fig. 3 | Trust lattice (5 levels, clearances of `system` / `instruction`) | §4.1 |
| Fig. 4 | Example diagnostic with taint path | §5 |
| Fig. 5 | Detection scores | `eval/results/detection.png` |
| Fig. 6 | Live ASR, direct and indirect | `eval/results/asr.png`, `asr_indirect.png` |
| Fig. 7 | Tensor Trust ASR | `eval/results/asr_tensor_trust.png`, `asr_indirect_tensor_trust.png` |
| Fig. 8 | Compile time vs. program size (log–log) | `eval/results/latency.png` |
| Table | Diagnostics reference (TL-L/P/S/W/G codes) | README §7 |

---

## Presentation notes (for the review, not for the paper)

**One-sentence pitch.** "Companies put a general LLM inside their own app with a secret system prompt; customers and documents can slip instructions into it. TrustLex is a compiler that refuses to build a prompt where that is possible — prepared statements for prompts."

**If asked "why not just filter bad words?"** Our keyword baseline catches only 56% of attacks that reach the system prompt and wrongly flags 30% of normal messages; attackers rephrase, filters can't keep up. TrustLex doesn't look for bad words — it controls *where* outside text is allowed to go.

**If asked "does it make the model safe?"** No — it makes the *prompt construction* safe. Anything typed is 100% blocked before the API call; free text is kept out of the system prompt and clearly marked, which cut indirect-attack success on gpt-oss-20b from 28% to 6%. A weak model (allam-2-7b) ignores the markers, which is exactly why the compile-time guarantee matters.

**If asked "where is the compiler design?"** Every classic phase is there: a PLY lexer with trust seeding, an LALR(1) parser with error productions and exact expected sets, semantic analysis with a type lattice and symbolic evaluation, an IR with integrity sealing, an optimizer with a proven correctness criterion, and target code generation to OpenAI/Anthropic payloads.

**If asked "what about API calls?"** The compiler's output *is* the API request: values stay JSON data, so they can't forge roles or messages; responses from other APIs are typed `from tool` and can't reach the system prompt raw; and the sealed IR stops anyone weakening the prompt between review and production.
