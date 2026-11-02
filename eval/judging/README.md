# Judging data

- `second_judge_labels.jsonl`: every label of the blind second judge (gemma-4-26b), one line per
  judged success, keyed `run|condition|item|repeat`; when an item was judged more than once (an
  unclear answer, or a first judgement made from a reply cut at 500 characters), the last line
  with `"full_reply": true` is the one used.
- `human_sheet_labelled.csv`: the 60 replies an author labelled blind (no layout, run or judge
  label), 30 drawn from each judge label; `human_sheet_key.json` maps its rows to the keys above.
  The author typed `COMPILED` for `COMPLIED`; it is read as the same label.
- Agreement: `python eval/rejudge.py --agreement eval/judging/human_sheet_labelled.csv`
  (60 rows: 88.3%, Cohen's kappa 0.76).

Tensor Trust and LLMail-Inject results do not depend on these labels: they are scored with each
set's own rule (`eval/native_metrics.py`). The judge is used for our own 32 attacks.
