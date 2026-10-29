# Prompt for building the final-review slide deck in Claude chat

## Files to attach (12)

Attach all of these in one message, then paste the prompt below.

| # | File | Why |
|---|---|---|
| 1 | `TrustLex IEEE Paper FInal edited.pdf` (your Downloads folder) | The final paper: the single source of truth for every claim and number |
| 2 | `paper/PAPER_CONTENT.md` | Longer write-up with extra explanation and the "Presentation notes" Q&A at the end |
| 3 | `eval/results/RESULTS.md` | Evaluation summary as produced by the harness |
| 4 | `eval/results/detection.png` | Chart: TrustLex vs. lexical linter vs. keyword filter |
| 5 | `eval/results/asr.png` | Chart: live attack success, our attacks, direct |
| 6 | `eval/results/asr_indirect.png` | Chart: live attack success, our attacks, indirect (RAG) |
| 7 | `eval/results/asr_tensor_trust.png` | Chart: Tensor Trust attacks, direct |
| 8 | `eval/results/asr_indirect_tensor_trust.png` | Chart: Tensor Trust attacks, indirect |
| 9 | `eval/results/latency.png` | Chart: compile time vs. program size |
| 10 | `examples/scenarios/01_safe_support_bot.tlx` | Code for the "a safe program" slide |
| 11 | `examples/scenarios/02_direct_injection.tlx` | Code for the "the compiler catches it" slide |
| 12 | `examples/scenarios/06_rag_indirect_injection.tlx` | Code for the indirect-injection slide |

Optional: if you want the demo slide to show real terminal output, run `python main.py demo` and paste the output or a screenshot as well.

---

## Prompt (copy everything below this line)

I need a PowerPoint deck (.pptx) for the final review of our Compiler Design course project (BCSE307L, VIT Vellore). We will present the slides and then give a live demo of the compiler. The attached files are our final IEEE-style paper (PDF), a longer write-up, the evaluation summary, six result charts and three example programs.

**Project.** TrustLex is a domain-specific language and compiler, written in Python with PLY. It treats *trust* as a type in LLM prompts. Each input declares where it comes from: the user, a retrieved (RAG) document, or a tool/API result. The compiler refuses to build any prompt in which untrusted text can reach the privileged system prompt without being sanitized. The motivation is prompt injection in companies' own LLM applications: website support bots, RAG assistants and agents that call APIs. All of these combine a custom system prompt with outside text.

**Team (title slide):**
- Amritha Varshini Pakanati (24BCE0390)
- V L Lakshmi Shriyaa (24BCE0778)
- Karthick Ganesh (24BCI0018)
- Guide: Dr. Krishnaraj N, Assistant Professor Sr. Grade 2, SCOPE, VIT Vellore
- GitHub: https://github.com/Karthick-Ganesh/TrustLex

### Ground rules
1. **Use only facts and numbers from the attached files.** The paper PDF wins over everything else. Never invent, round differently or "improve" a number. If a slide needs a value you cannot find, leave a visible placeholder like `[CHECK]` rather than guessing.
2. **Be honest about limits.** Show the limits as they are; the reviewers will ask. TrustLex guarantees *where* untrusted text goes, not how the model interprets it. In the direct scenario no difference between A, B and C is statistically significant. gpt-oss-20b on indirect Tensor Trust attacks has n=32 (free-tier daily token limit).
3. **Keep the text short.** At most about 5 bullets per slide and about 12 words per bullet. The details go in the **speaker notes** of every slide (3–6 sentences, in plain spoken English that a student can read aloud).
4. **Use the attached chart PNGs as images** on the result slides. Do not redraw them. Simple native tables are fine where they are clearer (e.g. the detection table).
5. **Show code in a monospace font** (e.g. Consolas) on a light-grey box, with the important line highlighted.
6. **Design:** clean and academic, 16:9, one accent colour (deep blue works with VIT) plus a red/green pair for unsafe/safe, a consistent title bar and slide numbers. No clip-art and no stock photos. Use simple shapes or diagrams where they help (pipeline, lattice, the conditions A–D).
7. **Speaker labels.** Split the talk roughly evenly between the three of us. Mark each slide's speaker in a small corner label and in the notes. Suggested split: Amritha (motivation → language), Lakshmi Shriyaa (compiler phases → type system → complexity), Karthick (evaluation → comparison → limits → demo).

### Slide plan (about 20 slides, 12–15 minutes before the demo)
1. **Title.** Paper title "TrustLex: Compile-Time Trust Typing for Injection-Safe Prompts in LLM-Integrated Applications", the team, the guide, SCOPE, VIT Vellore, the course code and the GitHub link.
2. **The problem.** Companies wrap a general LLM in their own app with a custom system prompt; customer messages, retrieved documents and API results are concatenated into the same prompt, so outside text can impersonate the developer. Mention that OWASP ranks prompt injection #1 for LLM apps.
3. **Direct vs. indirect injection.** A small diagram: an attacker types into the chat (direct), and an attacker plants text in a document or API response the app later retrieves (indirect).
4. **Our idea: the SQL analogy.** Prepared statements fixed SQL injection by changing how queries are *built*; TrustLex does the same for prompts. Also show the honest limit: unlike a database, the model still reads data with the same attention, so we guarantee placement, not interpretation.
5. **Literature review.** A compact version of Table I from the paper: DSPy/LMQL, CaMeL, TaintP2X, CSAS, PromptShield/NeMo, TrustLex. Columns: reasons about trust, when enforced, guarantee, per-request cost.
6. **The TrustLex language.** The support-bot program from Fig. 1 of the paper (or `01_safe_support_bot.tlx`). Explain `var`, `input … from rag|tool`, refinement types `pattern(...)` / `enum(...)`, `system {}` vs. `instruction {}`, and `sanitize()`.
7. **The compiler catches it.** `02_direct_injection.tlx` plus the `error[TL-S010]` diagnostic from the paper (taint path, `help:` fix-it). Say that the fix-it is verified before it is offered.
8. **Compiler pipeline.** Recreate Fig. 3 as a diagram: Lexer (trust seeds) → LALR(1) parser → AST → security checker → IR generation (checksummed, HMAC-sealed) → optimizer → bind() → OpenAI/Anthropic payload. Point out that only bind() runs per request.
9. **Compiler phases in detail.** One line each for lexical analysis, syntax analysis (no LALR conflicts, error productions, exact expected-token sets), semantic analysis, intermediate code, optimization and code generation. This maps the project onto the classic compiler-design syllabus.
10. **Security type system.** The five-level trust lattice TRUSTED ⊑ VALIDATED ⊑ SANITIZED ⊑ SEMI_TRUSTED ⊑ UNTRUSTED as a vertical ladder diagram, the clearances (system = SANITIZED, instruction = anything) and two or three of the typing rules in plain words.
11. **Exact, flow-sensitive analysis and the guarantee.** Symbolic evaluation with strong updates (an overwritten variable is clean again); `sanitize(u) + u` is still rejected. Non-interference theorem in one plain sentence, completeness (no false positives) and property-based testing with Hypothesis (500 random programs: 398 accepted, 102 rejected).
12. **Protecting API calls.** The three points from the paper: values stay JSON data so roles can't be forged; tool/API responses are typed and can't reach the system prompt raw; the sealed IR plus bind() re-checks stop silent weakening in production.
13. **Complexity analysis.** The big-O per phase; measured compile times (4.7 ms for 10 statements, 44 ms for 100, 207 ms for 500, 3.77 s for 5,000; about 5 ms for the example); `latency.png`. Also the worst case `a = a + a` and why an attacker can't reach it.
14. **Evaluation setup.** The corpus (48 programs, 32 attacks in 8 categories, 10 benign inputs), the baselines, the three live models, the Tensor Trust public benchmark (64 sampled attacks), the canary judge, and Wilson intervals with McNemar tests. Explain conditions A/B/C/D with a small visual.
15. **Detection and structural leakage.** `detection.png` plus the table: TrustLex F1 1.00, lexical linter 0.55, keyword filter 0.80. Structural leakage drops from 38.1% to 0% over 1,536 program–attack pairs; the keyword filter flags 30% of benign inputs.
16. **Live attack results.** Use `asr_indirect.png` and `asr_indirect_tensor_trust.png` as the headline (indirect is where the significant results are), with the key facts:
    - typed inputs (D) block 100% before any API call;
    - allam-2-7b with Tensor Trust attacks drops from 73.0% to 56.2% (p = 0.013);
    - gpt-oss-20b with our attacks drops from 28.1% to 6.2% (p = 0.016);
    - gemma-4 resists every condition.

    Put the direct charts in a backup slide.
17. **Comparison with existing work.** Table IV from the paper (B1, B2, Spotlighting, StruQ, CaMeL, TrustLex), with the caveat that the published numbers come from different models and attacks.
18. **Limitations and future work.** The honest list from the Limitations section, then future work: DAG-shared templates, control flow, multi-step agents, capability runtimes, a language server.
19. **Live demo.** A transition slide listing what we will show:
    - `python main.py demo` (13 scenarios, safe ones and caught injections);
    - the interactive REPL: type an unsafe program, see TL-S010, apply `:fix`, then enter an injection attack and see it sanitized and spotlighted in the final payload.

    Put the exact commands on the slide in code style.
20. **Conclusion + thank you.** Three takeaways and the GitHub link. Add a QR code to the link if you can generate one; otherwise just the link.

**Backup slides** (after the thank-you slide): `asr.png` and `asr_tensor_trust.png` (the direct scenario); the full Table III with all twelve rows; the five significant McNemar results; and short answers to likely questions, taken from the "Presentation notes" section of `PAPER_CONTENT.md`:
- "Why not just filter bad words?"
- "Does it make the model safe?"
- "Where is the compiler design?"
- "What about API calls?"

### Output
- One downloadable `.pptx` file, with speaker notes on every slide.
- Then list in chat every number you put on the slides, with the page or table of the paper it came from, so we can check it quickly.
- Also list any slide where you left `[CHECK]`.
