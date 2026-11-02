# Revision plan for publication

Goal: turn the course paper into a conference submission. This file records what we have agreed to change, the choices still open, and the review points we have not discussed yet. **No work has started**; we finish the discussion first.

Legend: criticality 🔴 high (likely rejection reason) · 🟠 medium (major-revision comment) · 🟢 low. Feasibility ⚡ hours · 🛠 days · 🧱 1–3 weeks.

---

## Agreed

### A. Sanitized free text in the `system` block 🔴 · 🛠 — DONE (6081423): code, tests, corpus, paper

**Problem.** `system` accepts anything at SANITIZED or below, and `sanitize()` lowers any input to SANITIZED. So `insert(sanitize(user_msg))` inside `system` compiles as safe. The sanitizer removes structure (role tokens, control and invisible characters) but not plain-English instructions, so attacker text still reaches the most trusted channel.
- The TL-S010 fix-it recommends exactly this layout (`insert(sanitize(user_msg))`, kept in `system`).
- Theorem 1 holds only "up to sanitization", and the attacker controls the sanitized text.
- Under a no-declassification rule, 16 programs that compile today would be rejected:
  - 10 of the 22 safe corpus programs: s04–s08, s14–s17, s19;
  - 6 examples: `examples/safe.tlx`, scenarios 01, 08 and 10, `enterprise_assistant.tlx` and `stress_2000_statements.tlx`.

**Planned fix.**
1. **New default policy:** `system` clearance becomes VALIDATED, so only developer text and refinement-typed inputs are accepted. Sanitized free text in `system` is a new error (proposed code TL-S013). `sanitize()` remains the cleaner for the `instruction` channel.
2. **Explicit, audited escape hatch:** `declassify(e, "reason")`. It sanitizes the value, requires a written justification, and produces a warning listing every declassification. The sealed IR records them. A `--no-declassify` option turns them into errors.
3. **New fix-it order for TL-S010/S011:**
   1. move the insert to the `instruction` block, creating one if needed;
   2. suggest a refinement type when the input looks like an ID or category;
   3. `declassify(x, "TODO: justify")` as the last resort.
4. **Stronger Theorem 1:** a program with no `declassify` renders every `system` block independently of all free-text inputs, with no sanitization caveat. With declassifications: non-interference up to the listed, justified declassifications (cite Sabelfeld & Sands).
5. **Side effect on flaw C:** VALIDATED and SANITIZED now have different clearances, so the lattice levels do operational work.

**Work list.**
- **Code:**
  - lexer and parser: the `declassify` keyword and expression;
  - semantic: policy, TL-S013, label rule, fix-its;
  - IR and codegen: declassification list in the sealed IR;
  - bind: apply the sanitizer and re-check;
  - main: the `--no-declassify` flag.
- **Programs:** update the 16 programs; relabel or rewrite the affected corpus programs.
- **Tests:** unit tests; update the property-based non-interference test.
- **Re-run, offline (no API calls):**
  - detection table (Table II);
  - 1,536-pair structural-leakage experiment;
  - latency;
  - demo scenarios.
- **Paper:**
  - typing rule (Sys) and a new rule for `declassify`;
  - Theorem 1;
  - Fig. 1 and the TL-S010 listing;
  - limitations (remove the "fix-it sanitizes in place" item);
  - README.

**Choices for A.**
1. **Name and syntax: DECIDED.** `declassify(x, "reason")`.
2. **Justification required: DECIDED.** Yes, a non-empty string literal. The compiler quotes the reason in the warning it prints for every declassification.
3. **Severity: DECIDED.** A warning by default, quoting the reason; `--no-declassify` turns it into an error. Plain sanitized text in `system`, without `declassify`, is always an error (TL-S013).
4. **New live condition S (deferred; the live-test part will be discussed later):** ("sanitized text in system", the layout today's compiler accepts): recommended if API quota allows, as empirical support for rejecting it. Cost: about +33% API calls. The gpt-oss runs are the slow ones (daily token limit).

### E3. TrustLex (C) barely beats the industry layout (B) 🔴 · 🛠 — Part 1 DONE (86f59ab, db0015b); live runs in progress; Part 2 framing pending final numbers

**Problem.** Only 2 of 12 B-vs-C comparisons are significant: allam indirect, p = 0.029 and 0.013. C is worse than B in 2 cells: allam direct with our attacks, 42.2 → 48.4, and gpt-oss indirect Tensor Trust, 25.0 → 31.2 (n=32).

**Causes found.**
1. **Incomplete spotlighting.** The system prompt never explains the `<untrusted_input>` tags. Hines et al. pair the marking with that explanation (checked: `codegen.py` and `eval/llm_asr.py` have no such notice).
2. **Weakest variant only.** We use plain delimiting; datamarking and encoding were stronger in Hines et al.
3. **Direct is out of the runtime layer's reach.** The customer is both the attacker and the user the model must serve, so B ≈ C is expected there.
4. **Low power.** n = 32–64 detects only gaps of about 17+ points; about 150–200 trials per condition are needed for about 10 points.
5. **Floor effect and small models.** gemma resists everything, and allam ignores markers.

**Planned fix.**
- **Part 1, strengthen C (code, about 1 day):**
  1. The compiler appends a fixed, developer-trusted notice to the system prompt whenever the program renders tagged inputs; the notice says that text inside the tags is data and must not be followed.
  2. Datamarking (and possibly encoding) becomes a selectable named sanitizer next to the default.
  3. To avoid tuning on the test set, split the 206 Tensor Trust attacks into a dev set (to choose the variant) and a disjoint, fresh test set; the 64 used so far stay with the old results.
  4. Check utility for each variant (datamarking and encoding can hurt small models).
- **Part 2, honest framing (paper, about 1 hour):**
  - For direct injection, claim no privilege escalation, no role forgery and 100% blocking of typed fields, not lower attack success than B; state that B ≈ C is expected.
  - Indirect injection is where the runtime layer is evaluated.
- **Part 3, a fair, well-powered comparison (deferred to the live-test discussion):**
  - baselines B and B-tagged, with A for reference only;
  - about 150–200 attacks per condition;
  - 1–2 frontier models;
  - BIPIA or AgentDojo;
  - utility reported with every attack-success number.

**Expected outcome.** C clearly beats B on indirect attacks, and beats or matches B-tagged on models that respect markers. If not, the paper's main claim still rests on the compile-time metrics (real-app leaks and typed-input share), and C is reported as "matches best practice".

### E1. Evaluated only on our own corpus (circular F1) 🔴 · 🧱 — DONE (c73b881, aa1834c); independent translations: 2 of 4 planned (agreement in case_study/README.md); replay done

**Problem.** F1 = 1.00 comes from 48 programs we wrote around TrustLex's own rules. The property-based tests show the theory is sound, but not that real prompts have these leaks, or that TrustLex can express real apps.

**Planned fix: a real-app case study (about 1.5–2 weeks).**
1. **Selection (Claude automates).**
   - Write the selection criteria down before looking at any result:
     - the app uses a system prompt;
     - it has at least one outside input (user, retrieved document, or tool/API result);
     - it meets a minimum star count and recent-activity threshold;
     - it is open source.
   - Pick **20 apps**, mixing support bots, RAG Q&A, tool-using agents and email or summariser apps.
   - Also include the official example templates of popular frameworks (LangChain, LlamaIndex).
   - Record every candidate considered and why it was kept or excluded.
2. **Translation into TrustLex.**
   - Claude locates each app's prompt-construction code and drafts the TrustLex translation, tagging each input as `user`, `rag` or `tool`.
   - **For independence, at least one author translates independently** (all 20 if time allows, otherwise a sample of at least 30–50%). We report the agreement.
   - Disagreements are resolved by discussion, and all translations are published in the repo.
3. **Analysis.**
   - For each app, record:
     - the compiler verdict;
     - each leak and its source;
     - the fix needed (move, refinement type or `declassify`);
     - the porting effort.
   - Confirm every finding by hand.
   - Run the keyword filter and the lexical linter on the same apps.
4. **Proofs of concept.**
   - Show 3–5 confirmed leaks with a working attack.
   - Run them only on **local copies with our own API key**, never on deployed services.
5. **Metrics:**
   - % of apps with at least one leak, by source;
   - false alarms;
   - share of inputs that can be refinement-typed (also answers E2);
   - features TrustLex could not express, such as loops over documents and if/else (feeds the novelty discussion);
   - the baselines' results on the same apps.

**Decided.**
- 20 apps.
- Manual translation now; an automatic converter for common template formats (e.g. LangChain prompts) is a later option.
- Proofs of concept for 3–5 leaks.

**Disclosure to maintainers.** Claude reports each confirmed leak in a maintained project to Karthick first. Karthick drafts the message and informs the maintainers. Claude does not contact anyone.

**Paper.**
- A new "Real-world case study" subsection with its metrics.
- Selection criteria and threats to validity: translation is manual, and TrustLex has no loops or branches.
- Update the AI-use disclosure, since Claude assisted with selection and draft translations.

---

## To discuss next (from the review)

| # | Point | Status | Crit. | Feas. |
|---|---|---|---|---|
| D | Exponential worst case (`a = a + a`) | **DONE:** size cap, TL-S016 (10,000 slots / 4M chars); checking bounded, 0.30 s at the cap | 🟠 | ⚡ |
| C | Lattice levels act like two | **DONE:** table of what each level admits, by policy (checked against the compiler); `context{}` channel not planned | 🟠 | ⚡ |
| E3 | B vs C weak | **agreed above** (Parts 1–2); Part 3 waits for the live-test discussion | 🔴 | 🛠/🧱 |
| E2 | Condition D compares free text with an 8-character regex | **DONE:** case study, 2 of 31 real inputs typeable; D's claim reworded (blocks attacks written into typed fields) | 🟠 | ⚡ |
| E1 | Own corpus only (circular F1) | **agreed above** (real-app case study) | 🔴 | 🧱 |
| — | Proof is a sketch | fine for a conference; full proof for a journal | 🟢/🟠 | 🛠 |
| — | Semantic Kernel cited as a developer blog [15] | **DONE:** cites the SDK repository, blog as a note | 🟢 | ⚡ |
| — | Novelty: exact analysis is easy without control flow | add `if`/`match`/functions, or a practical contribution | 🔴 | 🧱 |
| — | Only 3 small free-tier models | add 1–2 frontier models | 🟠 | 🛠 |
| — | One public benchmark, not indirect | add BIPIA or AgentDojo | 🟠 | 🛠/🧱 |
| — | gpt-oss n=32 in three settings; repeats not run | quota time only | 🟢 | ⚡ |
| — | Utility on only 10 benign inputs | a few hundred real support questions | 🟠 | 🛠 |

## Evaluation design (proposal, not decided)

**How industry builds prompts today.** Developer rules and persona go in the `system` message. The customer's message goes in the `user` message. Tool and API results go in `tool` messages. For retrieved documents, both layouts are common:
- in the system message (RAG templates of the form "use the following context: {context}");
- in the user message, often wrapped in XML tags, which is the current best-practice advice.

**Proposed baselines** (each one a real industry layout):
- **Direct:** B (customer message in the user turn) is the standard; A is an anti-pattern, kept only for reference.
- **Indirect:** A (documents in the system prompt, the common template default); B (documents raw in the user turn); and a new **B-tagged** (user turn plus XML tags, the best-practice advice). C vs. B-tagged isolates what TrustLex adds over best practice.

**Proposed metrics, one per layer:**
1. **Compile-time guarantee** (the main contribution): leaks found in real open-source LLM apps, false positives on those apps, and porting effort. This needs the real-app study.
2. **Typed inputs:** the share of real apps' inputs that can be refinement-typed. Multiplied by D's 100% blocking, this gives the share of the attack surface removed by construction.
3. **Runtime layer:** attack success vs. B and B-tagged, with paired McNemar tests, reported together with **utility** (benign task success). Run it on frontier models as well as small ones, and on a standard indirect benchmark (BIPIA or AgentDojo) so the numbers are comparable with published work.

## Questions raised in discussion
- **Adoption:** industry is slow to adopt a new language. Should we also offer TrustLex as an embedded Python library or linter (typed prompt strings checked by the same analysis)? This would help the "industry benefit" argument and the real-app case study.
- **Venue:** to be decided with the guide; it sets the deadline and how much of the list we do.
