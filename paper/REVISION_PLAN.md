# Revision plan for publication

Goal: turn the course paper into a conference submission. This file records what we have agreed to change, the choices still open, and the review points we have not discussed yet. **No work has started**; we finish the discussion first.

Legend: criticality 🔴 high (likely rejection reason) · 🟠 medium (major-revision comment) · 🟢 low. Feasibility ⚡ hours · 🛠 days · 🧱 1–3 weeks.

---

## Agreed

### A. Sanitized free text in the `system` block 🔴 · 🛠 — AGREED, not started

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

---

## To discuss next (from the review)

| # | Point | Status | Crit. | Feas. |
|---|---|---|---|---|
| D | Exponential worst case (`a = a + a`) | rebutted in paper, not fixed in code; fix = DAG / hash-consed templates | 🟠 | 🛠 |
| C | Lattice levels act like two | one sentence in paper; A partly helps; option: a `context{}` channel for RAG data at SEMI_TRUSTED | 🟠 | 🛠 |
| E3 | B vs C (realistic comparison) weak; gpt-oss TT indirect C worse than B | reported honestly; needs more n, models, baseline defences | 🔴 | 🛠/🧱 |
| E2 | Condition D compares free text with an 8-character regex | labelled "by construction"; needs evidence of how often real inputs can be typed | 🟠 | 🧱 |
| E1 | Own corpus only (circular F1) | wording fixed; needs a real-app case study | 🔴 | 🧱 |
| — | Proof is a sketch | fine for a conference; full proof for a journal | 🟢/🟠 | 🛠 |
| — | Semantic Kernel cited as a developer blog [15] | text mention only | 🟢 | ⚡ |
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
