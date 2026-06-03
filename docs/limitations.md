# Known limitations

Each entry references the decision it follows from (see
[decisions.md](decisions.md)).

## L-1. Thin benign baseline → softer precision than production

**Origin.** D-1, D-4.

Public LOTL corpora (OTRF, attack_data, EVTX-ATTACK-SAMPLES) are
attack-centric; their benign content is whatever Windows housekeeping
happened during the capture window. After labeling, the test-set neg/pos
ratio sits at ~50:1–200:1 depending on which subset you load — close to
production order-of-magnitude but with much less *diversity* in negatives.

**Symptom.** Precision-at-recall-0.95 will be lower than what a well-tuned
classifier could achieve at scale, and the model may be over-confident on
benign LOLBin usages it never saw in training (e.g. legitimate
`schtasks /create` for backups, MSBuild compiles of OSS projects).

**Mitigation.** The brief recommends generating a 7–14 day benign Sysmon
capture on a Windows 10/11 VM with Hartong's `sysmonconfig-research.xml`
and GHOSTS-driven activity. Not in scope for this codebase yet.

## L-2. Sysmon config drift across sources

**Origin.** D-1.

OTRF uses OTRF Blacksmith's config, attack_data uses Attack Range default,
EVTX-ATTACK-SAMPLES mixes configs across years. Fields like
`OriginalFileName`, `IntegrityLevel`, and `RuleName` are not uniformly
present.

**Symptom.** `renamed_lolbin` (which needs `OriginalFileName`) degrades to 0
on captures where the field is missing — looks like a benign feature when
in reality the data is just incomplete.

**Mitigation.** Loaders default missing fields to empty strings rather than
raise. Features degrade gracefully. A more rigorous fix would normalize
through OSSEM ([github.com/OTRF/OSSEM](https://github.com/OTRF/OSSEM))
before feature extraction.

## L-3. Coverage gaps in public data for newer LOLBins

**Origin.** D-1, D-3.

Across all three corpora, `msdt.exe` (Follina, T1218.014), `finger.exe`,
`forfiles.exe`, and `OneDriveStandaloneUpdater.exe` are underrepresented
because they emerged after most public captures were recorded.

**Symptom.** The model will be naive on these techniques and may
misclassify novel LOLBin invocations.

**Mitigation.** Execute the corresponding Atomic Red Team atomics in a
Sysmon-instrumented lab and contribute the captures back with clean labels.
Not in scope here.

## L-4. Hand-curated LOLBAS catalog can drift from upstream

**Origin.** D-3.

`train_utils/lolbas.py` ships ~40 high-signal LOLBins. LOLBAS adds
entries periodically; without a refresh step, the catalog becomes stale.

**Symptom.** Newly-cataloged LOLBins won't be labeled positively.

**Mitigation.** `fetch_lolbas_live()` exists for ad-hoc refresh runs. A
better long-term fix would be a CI job that diffs the catalog and opens a
PR — out of scope for the thesis.

## L-5. Capture-level "malicious" flag still trusts the source manifest

**Origin.** D-4.

If a corpus is mislabeled (capture says malicious but events are benign, or
vice versa), the propagation rule can't recover.

**Symptom.** Mislabeled captures add either false positives (benign events
labeled 1 because they're LOLBins in a "malicious" capture) or false
negatives (entire attack chain labeled 0).

**Mitigation.** Spot-check the labeled positives by hand for the first few
runs. The propagation rule lives in `train_utils/labeling.py`; a regression
test asserting that only descendants of a malicious root are marked would be
the right anchor here. No automated test suite ships with the pipeline yet.

## L-6. EID-3 / EID-11 windowing assumes the same `ProcessGuid` is consistently set

**Origin.** F-1, D-5.

EVTX-ATTACK-SAMPLES captures sometimes lack `ProcessGuid` on EID 3/11
events when older Sysmon versions were used.

**Symptom.** `net_connects_60s` and `files_written_60s` features
under-count for affected captures.

**Mitigation.** Could fall back to `(Image, time)` proximity matching, but
that's noisier than GUID matching; left as-is for now and documented here.

## L-7. Hashing-vectorizer collisions for short CommandLines

**Origin.** F-2.

`HashingVectorizer(n_features=1024)` collides ~3-5% of distinct trigrams
into the same bucket. For short CommandLines (e.g. `"notepad.exe"`) the
hashed representation is nearly degenerate.

**Symptom.** Model trades a small amount of distinguishability for not
having to fit a vocabulary. PR-AUC ceiling is slightly lower than a fitted
TF-IDF approach.

**Mitigation.** Bump `n_features` to 4096 if a future ablation shows it
matters; currently it doesn't move PR-AUC noticeably.

## L-8. `scale_pos_weight` doesn't fix data-poor positive classes

**Origin.** M-2.

When the training set has fewer than ~100 positives (small dataset stacks),
`scale_pos_weight = neg/pos` puts huge weight on a tiny number of examples.
The model overfits whatever idiosyncrasies those examples have.

**Symptom.** Train aucpr saturates at 1.0 within 50 boosting rounds (the
synthetic smoke run showed exactly this).

**Mitigation.** Increase the number of malicious captures (stack more
corpora) or downsample negatives so the absolute counts are saner. The
real-data run uses all three corpora and should land in the 1k+ positives
range.

## L-9. The classifier is per-event; no chain-level reasoning

**Origin.** D-5.

The model predicts whether *this launch* is LOTL. A multi-stage attack
chain is detected only if its constituent launches are individually
suspicious.

**Symptom.** A "low-and-slow" chain that uses one weakly-anomalous LOLBin
per stage may slip below the per-event threshold even though the chain as
a whole is highly suspicious.

**Mitigation.** Out of scope for binary classification — a chain-level
detector would aggregate per-process scores over the process tree and
trigger on the maximum or some weighted sum. Reasonable thesis follow-up.

## L-10. License compatibility for released model artifacts

**Origin.** D-1.

EVTX-ATTACK-SAMPLES is GPL-3.0. OTRF Security-Datasets is MIT/GPL-3.0
(mixed). Splunk attack_data is Apache-2.0.

**Symptom.** A model trained on all three may be argued to be a derivative
work of GPL-3.0 data. Releasing the model weights publicly without
clarifying license posture is risky.

**Mitigation.** For the thesis, document the training corpora and their
licenses. If artifact release is required, train a separate
GPL-free model on OTRF + attack_data + a self-generated corpus only.

## L-11. Only ~30 positive captures → wide CV confidence intervals

**Origin.** D-1, D-7, M-7.

After labeling (LOLBAS ∩ ATT&CK + process-tree propagation), the union of
all three public corpora produces around 30 distinct *malicious LOTL
captures*, distributed across ~8 parent ATT&CK techniques. Event-count per
capture varies from 3 to 220.

**Symptom.** Even with K-fold CV on stratified+clustered splits, the
headline metrics have wide bands: event-level PR-AUC = 0.38 ± 0.20,
capture-level PR-AUC = 0.42 ± 0.17. The model itself is fine — the dataset
isn't large enough to evaluate it tightly. The most stable metric in this
regime is **capture-level ROC-AUC ≈ 0.81 ± 0.05**.

**Mitigation.** Acquire more positive captures, especially for techniques
with single-digit representation (T1197, T1220, T1548 in the current
corpora). The cleanest path is running Atomic Red Team atomics for those
techniques in a Sysmon-instrumented VM, capturing the events with the
canonical schema, and adding them to the dataset stack. Out of scope for
the current thesis.

## L-12. K-fold can produce degenerate folds when positive captures are scarce

**Origin.** D-7, M-7.

With `N_FOLDS=5` and ~30 positive captures distributed across strata of
size 1–10, the round-robin K-fold assignment occasionally lands a fold
with only 1 positive capture in test (out of ~45 captures). On such a
fold, recall@top-10% can only take values {0, 1} (binary), and PR-AUC is
essentially noise.

**Symptom.** Cross-fold mean ± std is inflated by these degenerate folds.
In the current run, fold 5 has 1 positive capture, PR-AUC ≈ 0.01, F1 ≈
0.03, and drags the cross-fold mean from a credible ~0.50 down to 0.42.

**Mitigation.** A "skip folds with fewer than N test positives" guard
before averaging would make the summary more honest. Not added yet
because it would mask the underlying L-11 problem; the visible
degeneracy is a useful "you need more data" signal.

## L-13. Standalone autonomous alerting is not viable; cascade is required

**Origin.** D-1, D-7, M-10.

The ML tier on its own cannot reliably hit precision ≥ 0.95 at usable
recall. `precision_at_p95 = 0.60 ± 0.49` capture-level — in about half
the folds the model cannot reach 95% precision *at any threshold*. This
isn't a tuning problem; it's a structural consequence of L-11.

**Symptom.** A direct ML-only deployment ("alert when score > T")
produces too many false positives at SOC-acceptable recall, or too few
true positives at SOC-acceptable precision.

**Mitigation.** Deploy as Tier 2 of the cascade in M-10 — let the LLM tier
provide last-mile precision. The ML tier's role is to rank, not to
alert; this is reflected in the evaluation metric set (M-6) and the
project-level memory `project_cascade_architecture.md`.
