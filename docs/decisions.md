# Design decisions

Every non-trivial choice made while building the ML pipeline, with context,
rejected alternatives, and a source. "Source: brief" means the choice came
directly from the LOTL methodology brief that anchors this thesis; "source:
mine" means it's a judgment call I made, with the rationale stated.

## Data

### D-1. Stack OTRF + Splunk attack_data + EVTX-ATTACK-SAMPLES

**Context.** No single public Sysmon corpus is a turnkey LOTL training set;
each has gaps in either coverage or benign baseline.

**Choice.** Train on the union of OTRF Security-Datasets (positives,
labeled), Splunk attack_data (positives, T-coded), and EVTX-ATTACK-SAMPLES
(positives, broad LOLBin breadth).

**Rejected.**
- *DARPA OpTC alone.* 1.1 TB, days-long benign volume — too heavy as a
  training set; reserved for honest held-out evaluation in future work.
- *TON_IoT / LANL / CICIDS.* No `CommandLine` field, which makes
  `certutil -urlcache` indistinguishable from benign `certutil`.
- *EMBER / SOREL-20M.* Static PE classification, not runtime telemetry.

**Source.** Brief.

### D-2. Canonical schema mirrors the Rust agent's output

**Context.** Each public corpus uses a different on-disk shape — OTRF uses
Winlogbeat ECS (`winlog.event_data.*`), Splunk uses XmlWinEventLog flattened,
EVTX is BinXML.

**Choice.** Pick one canonical shape and convert everything to it before
labeling. The shape is the one `apps/sysmon_agent` already emits:
`{record_id, event_id, level, provider, channel, computer, time_created,
data: {…flat Sysmon EventData fields…}}`.

**Rejected.**
- *Match OTRF's ECS shape.* Would require the agent to nest under
  `winlog.event_data` and break the existing JSON contract.
- *Match raw EVTX BinXML.* Verbose and not how anyone consumes Sysmon
  downstream.

**Source.** Mine. Picked the agent's schema because the agent is the
production data path and changing it later would be expensive.

### D-3. Curated, in-code LOLBAS catalog (not live fetch)

**Context.** LOLBAS publishes a JSON catalog at
`lolbas-project.github.io/api/lolbas.json` that lists ~190 binaries with
MITRE T-code mappings.

**Choice.** Hardcode ~40 high-signal entries directly in
`train_utils/lolbas.py` and expose `fetch_lolbas_live()` as an optional
network call.

**Rejected.**
- *Always fetch live.* Adds a network dependency to training and makes
  labels non-deterministic if the catalog changes between runs.
- *Vendor a full snapshot at 190 entries.* Adds ~40 KB of low-signal entries
  that don't appear in the public corpora often enough to matter for the
  classifier.

**Source.** Mine. Determinism and reproducibility for thesis comparisons.

### D-4. Process-tree label propagation, not capture-level labels

**Context.** Malicious captures contain not just the attack payload but
Windows housekeeping events (svchost, explorer, etc.) that fire during the
capture window.

**Choice.** A process is labeled LOTL=1 only when it is in the closure over
`ProcessGuid → ParentProcessGuid` starting from a malicious root, *or* when
it is a LOLBin in a malicious capture (rule a). Everything in benign
captures is 0 by construction.

**Rejected.**
- *Every event in malicious captures = 1.* Too noisy — the model would
  learn that incidental `svchost.exe` is LOTL whenever it co-occurs with
  an attack.
- *Pure LOLBAS membership.* Misses follow-on non-LOLBin children that
  complete an attack chain.

**Source.** Brief explicitly warns capture-level labeling is too noisy.

### D-5. Classify only Sysmon EID 1 (process creation)

**Context.** Sysmon emits 25+ event IDs. EID 3 (network connection) and
EID 11 (file create) carry signal but are not "did an attack just launch?"
decisions.

**Choice.** Score only process-creation events. Use EID 3 and EID 11 as
*features* on EID 1 rows (the 60-second post-launch network/file activity
attributed to the new process by `ProcessGuid`).

**Rejected.**
- *Score every event independently.* Mixes two different prediction problems
  and inflates the negative pool with EID-7 image loads that don't matter.
- *Aggregate per process and score once.* Loses time resolution — the
  classifier would predict "this was a bad process at some point" instead
  of "this launch was bad."

**Source.** Mine. Matches how SIEM detections actually fire (per-launch).

### D-6. `capture_id` = relative directory path under each dataset root

**Context.** GroupShuffleSplit needs stable, deterministic group IDs so the
same capture lands in the same fold across runs.

**Choice.** Use the path relative to the dataset root, posix-style. E.g.
`atomic/windows/execution/host/T1059.001_Empire`.

**Rejected.**
- *UUID per ingest.* Not deterministic across reruns.
- *Filename only.* Captures with duplicate filenames across folders would
  collide.

**Source.** Mine.

### D-7. Train/val/test split: capture-grouped, technique-stratified, feature-cluster-refined, K-fold

**Context.** Two events in the same capture share `ProcessGuid` chains,
sibling-cluster artifacts, host fingerprints, and time of day. Splitting by
event leaks signal across the boundary. But naive capture-grouped splits
break in a second, subtler way: positives are concentrated in ~30 captures
across a handful of ATT&CK technique families, so a random capture-grouped
split routinely puts all of one family in train and another in val/test —
producing a train aucpr ≈ 0.88, val aucpr ≈ 0.07, best_iteration = 0
failure mode (the model never learned anything that generalizes).

**Choice.** Three-layer split logic, all in `train_utils/splitting.py`:

1. **Capture-grouped**: every event from a `capture_id` lands in the same
   fold. Foundation, not negotiable.
2. **Technique-stratified**: each capture is assigned a stratum by primary
   LOTL technique rolled up to parent code (T1218.005 → T1218); benign
   captures share a `"neg"` pool. Each stratum is sliced independently so
   every fold sees every technique family.
3. **Feature-cluster-refined**: within each stratum, captures are clustered
   by mean L2-normalized n-gram signature (k-means, k=2-3) — so two LSASS
   campaigns don't both end up in train while two mshta captures hide in
   val. Strata below `MIN_CLUSTER_SIZE` (6) are not subdivided — clustering
   2-3 captures is noise, and the n=2 split fallback starves val.
4. **K-fold (`N_FOLDS=5`)**: each capture appears in test exactly once across
   the K folds. The CV summary is the headline; single-fold metrics are
   noise (see M-7).

**Rejected.**
- *Stratified random split on events.* Standard practice but produces
  unrealistically optimistic numbers — the model is partially memorizing
  capture-level fingerprints rather than learning the LOTL signal.
- *Plain `GroupShuffleSplit` (capture-grouped, unstratified).* What the
  pipeline originally did. Fails as described above.
- *`StratifiedGroupKFold` from sklearn directly.* It stratifies by a single
  label per group, which would force us to choose between technique label
  and feature cluster. Our hand-rolled split combines both and gives
  explicit fallbacks for tiny strata.
- *Split by host.* Stronger, but most public captures are single-host.

**Source.** Brief required capture-grouped splitting; the stratification,
feature-cluster refinement, and K-fold are mine, motivated by an empirical
investigation of why the original split produced unstable metrics.

### D-8. Test set held at natural imbalance; only train may be downsampled

**Context.** Production neg/pos ratio is roughly 100:1. Rebalancing the test
set to 50:50 inflates precision by 1-2 orders of magnitude.

**Choice.** `downsample_majority(...)` in `splitting.py` is opt-in via the
`TRAIN_RATIO_CAP` knob and operates only on train rows. Test is whatever the
data gives.

**Rejected.**
- *Train and test on rebalanced data.* The headline-grabber, the wrong
  answer. Brief calls this out as a "common trap."
- *SMOTE the minority class.* Synthetic CommandLines don't exist; SMOTE on
  hashed n-grams produces nonsense features.

**Source.** Brief.

## Features

### F-1. Three feature layers + character n-grams

**Context.** A single attack signal is rarely in any one event; LOTL chains
have local (cmdline shape), structural (who spawned whom), and contextual
(what else launched at the same time) tells.

**Choice.** Three dense layers, then hashed character 3-5-grams on top:

1. *Process-local*: CommandLine length, Shannon entropy, base64/hex blob
   presence, `-enc`/`IEX`/`DownloadString` flags, URL count, special-char
   ratio, image path depth, Temp/AppData flag, `renamed_lolbin` flag.
2. *Parent-child*: Office/browser parent flags, hard-coded
   suspicious-pair lookup (winword→cmd, outlook→mshta, etc.).
3. *Session*: per-`ParentProcessGuid` sibling count and sibling-LOLBin count
   in a 5-minute window; per-`ProcessGuid` EID 3 / EID 11 count in a
   60-second window.

**Rejected.**
- *Process-local only.* Misses the Office→regsvr32 phishing chain signal.
- *No n-grams.* CommandLine is the highest-bandwidth source of signal;
  ignoring its text loses the obfuscation/payload structure tells.

**Source.** Three-layer scheme is from the brief; specific feature names are
mine.

### F-2. Hashed character n-grams over fitted TF-IDF

**Context.** CommandLines are obfuscated, sometimes base64-encoded, often
contain typos and renames. A fitted vocabulary built on the train set won't
generalize to unseen substrings at inference.

**Choice.** `sklearn.HashingVectorizer(analyzer="char_wb", ngram_range=(3,5),
n_features=1024, alternate_sign=False, norm="l2")`. Stateless — same dims
at train and inference, no fit step.

**Rejected.**
- *`TfidfVectorizer`.* Needs `fit`, brittle when CommandLine vocabulary
  shifts between train and test.
- *Word-level tokenization.* Loses signal inside flags like
  `-EncodedCommand` and in concatenated obfuscation.
- *Higher `n_features` (8192+).* Negligible PR-AUC gain in pilot runs, 8×
  the booster memory.

**Source.** Brief recommends 1024 dims and char 3-5-grams; hashing vs TF-IDF
is mine.

### F-3. 5-minute session window, 60-second effects window

**Context.** "Sibling processes" is a meaningful concept only inside a
bounded time window; the same parent shell may legitimately spawn unrelated
children hours apart.

**Choice.** Session window = 5 minutes (`SESSION_WINDOW` in `features.py`),
effects window = 60 seconds (`EFFECTS_WINDOW`). Implemented with a
two-pointer sweep per `ParentProcessGuid` to keep the feature builder
O(n log n) instead of O(n²).

**Rejected.**
- *1-minute session window.* Misses the typical Office macro → staging →
  callback pattern, which can span 2–3 minutes.
- *Whole-capture aggregation.* Inflates feature values for long benign
  captures and disadvantages short malicious ones.

**Source.** Brief specifies these values.

### F-4. Hard-coded "suspicious parent-child pair" lookup

**Context.** Office spawning cmd/powershell, outlook spawning mshta, and
similar are textbook initial-access patterns; the model benefits from a
strong prior here rather than having to discover them from scratch.

**Choice.** Maintain `SUSPICIOUS_PAIRS` in `features.py` as a hand-curated
set of `(parent_basename, child_basename)` tuples. Boolean feature
`suspicious_pair`.

**Rejected.**
- *Learned pair embeddings.* Not enough training data to learn the long tail.
- *No prior.* The model finds these eventually, but with weaker confidence
  and more false positives on rare-but-benign pairs.

**Source.** Mine.

### F-5. `renamed_lolbin` flag uses `OriginalFileName`, not file hash

**Context.** A common evasion is to copy `powershell.exe` to
`C:\Users\Public\update.exe`. The PE header's `OriginalFileName` field still
says "PowerShell.EXE".

**Choice.** Boolean: `OriginalFileName.lower() != basename(Image).lower()`
and the basename is not itself a known LOLBin.

**Rejected.**
- *Hash-based provenance.* Requires a known-good catalog of MS-signed hashes
  per Windows version — out of scope.
- *Signer-based.* Sysmon does emit signature fields, but they're not
  uniformly populated across public corpora.

**Source.** Mine. Cheap, high-signal, robust to renames.

## Model

### M-1. XGBoost, not a neural net / random forest / logistic regression

**Context.** The feature matrix is mixed sparse + dense, tabular, with
strong hand-engineered features and ~10⁴–10⁶ rows per realistic training
set. We need calibrated probabilities for thresholding at deployment time.

**Choice.** Gradient-boosted trees via XGBoost.

**Rejected.**
- *Neural net.* Tabular data with engineered features is XGBoost's sweet
  spot; NNs need 10×+ more data to match.
- *Random Forest.* Comparable accuracy but worse calibration and slower at
  inference time.
- *Logistic regression.* Strong baseline but can't model the n-gram ×
  parent-child interactions that matter most here.

**Source.** Brief recommends XGBoost.

### M-2. `scale_pos_weight = neg/pos`, not SMOTE/undersampling

**Context.** Class imbalance is 100:1+ in production. The classifier has to
care about positives without inventing them.

**Choice.** Per-instance weighting via `scale_pos_weight`. Computed
automatically as `(y_train == 0).sum() / (y_train == 1).sum()` in
`train.py`.

**Rejected.**
- *SMOTE.* Synthetic CommandLines are meaningless; SMOTE on hashed n-grams
  produces unparseable feature combinations.
- *Random undersampling.* Throws away majority-class diversity.
- *Class weights in the loss.* Equivalent to `scale_pos_weight`; we use
  XGBoost's native knob for clarity.

**Source.** Brief.

### M-3. `tree_method="hist"`, not `"exact"` or `"approx"`

**Context.** Histogram-binned splits scale to millions of rows with
negligible accuracy loss; exact is O(n log n) per split per feature.

**Choice.** `hist`. Default in modern XGBoost (≥1.6).

**Rejected.**
- *exact.* Slower, no win on this feature distribution.
- *gpu_hist.* No GPU assumption; thesis lab is CPU-only.

**Source.** Brief.

### M-4. Track both `aucpr` and `logloss`; early-stop on `logloss`

**Context.** ROC-AUC is inflated by the easy-to-classify majority class at
high imbalance, so PR-AUC is the right *reporting* metric. But for early
stopping, val PR-AUC is noisy on small validation folds — a single
malicious capture flipping rank can move val aucpr by several points
between rounds, masking real progress. Logloss, computed over every val
event, is smoother and reflects probability calibration rather than just
top-of-ranking ordering.

**Choice.** `eval_metric = ["aucpr", "logloss"]`. XGBoost uses the last
metric in the list for early stopping, so the boost loop stops when val
logloss stops improving while val aucpr is still logged every round. We
record both `best_val_logloss` and `best_val_aucpr` on `TrainedModel`.
`early_stopping_rounds=50`, `num_boost_round=600`.

**Rejected.**
- *Early stop on `auc` (ROC).* Plateaus quickly because the negative class
  is too easy.
- *Early stop on `aucpr` only.* What the pipeline originally did. With ~30
  positive captures and ~50 positive events per val fold, val aucpr
  bounced enough that the model frequently early-stopped at iteration 0
  — empirically the worst case.
- *Early stop on `logloss` without tracking aucpr.* Loses the reporting
  metric in the per-round log.
- *No early stopping.* Risks overfitting given the small positive count.

**Source.** Mine. Brief specified aucpr; the noise-driven switch to logloss
for early stopping came from observing best_iteration = 0 on the original
pipeline and tracing it back to val-aucpr instability.

### M-5. Reasonable XGBoost defaults: `max_depth=8`, `lr=0.08`, `subsample=0.9`, `colsample_bytree=0.8`, `reg_lambda=1.0`

**Context.** Tuning hyperparameters needs a held-out set; no production
dataset to tune against yet.

**Choice.** Sensible mid-strength defaults; documented as constants in
`main.py` so they show up in MLflow as logged params on every run.

**Rejected.**
- *Auto-tune via Optuna.* Premature — first stabilize the pipeline, then
  tune.
- *Aggressive depth (10+).* Trees memorize per-capture artifacts at small
  pos counts.

**Source.** Mine.

### M-6. Evaluation reports: ranking quality + precision floors + recall-at-top-K, at both event and capture level

**Context.** A single metric doesn't satisfy a thesis defense, and a single
*level* of evaluation doesn't reflect how the model is used in the
cascade. Reviewers want deployment-relevant trade-offs; the cascade
operator wants ranking quality and top-K recall (see M-10).

**Choice.** Each fold produces two parallel `EvalReport`s — one event-level
(`evaluate(y, score)`), one capture-level (`evaluate_capture_level(y, score,
capture_ids)`, which max-aggregates event scores per capture before
scoring). Both compute the same field set:

- *PR-AUC, ROC-AUC*: ranking quality at imbalanced threshold range.
- *Best F1 + threshold + precision/recall there*: the classifier's
  no-context "sweet spot."
- *Precision floors* (`PRECISION_FLOORS = (0.80, 0.95, 0.99)`): max recall
  achievable while keeping precision ≥ each floor — the "could it autopilot
  at this precision target?" diagnostic.
- *Recall at top-K* (`TOP_K_PERCENTILES = (0.01, 0.05, 0.10)`): the primary
  metric for cascade ranking — "if the LLM tier reviews the top K% of
  events, how many true positives reach it?"
- *Test imbalance ratio*: never hidden; reported with every run.

Cross-fold mean ± std is logged for every field at both levels. Capture-level
ROC-AUC is the most stable headline number (~0.05 std on ~30 positive
captures); event-level is reported but noisier.

**Rejected.**
- *Accuracy.* Useless at 100:1 imbalance — predicting "0" always scores 99%.
- *Single precision floor (p95 only).* Original pipeline did this; replaced
  with three floors so the trade-off curve is legible.
- *Event-level only.* Cascade operates capture-by-capture; event-level
  metrics over-weight chunky captures with 100+ events.
- *Capture-level only.* Loses the per-event signal that the agent emits.
  We report both.
- *Confusion matrix only.* Threshold-dependent without context.

**Source.** Mine. Brief specified PR-AUC over ROC-AUC and the F1/precision@95
split; the cascade-shaped metric set (recall@top-K, dual-level eval) came
from user discussion about the YARA→ML→LLM+RAG architecture (see M-10).

### M-7. K-fold cross-validation as the canonical evaluation, not a single test split

**Context.** Single-fold test metrics swung wildly between runs (PR-AUC
0.38 → 0.89 across four runs with otherwise similar setups) — not because
the model changed, but because *which 4–6 positive captures landed in test*
dominated everything, and per-capture event counts range from 3 to 220.
With only ~30 positive captures globally, no single split is representative.

**Choice.** `stratified_capture_kfold` produces `N_FOLDS=5` train/val/test
triples where each capture appears in test exactly once. Per fold: train a
fresh model, evaluate at both event and capture level (M-6), log metrics
keyed by fold index. The headline summary is mean ± std across folds —
single-fold numbers are diagnostic only.

The canonical "production" model saved to `data/lotl_xgb.json` is the fold
with the lowest val logloss. This is defensible ("the model that
generalized best on its own val split") but acknowledged as one choice
among several reasonable ones — it does not change the headline CV
metrics.

**Rejected.**
- *Single split (the original pipeline).* Misleading variance, as
  documented above.
- *Multi-seed sweep on a single split.* Half-measure — averages over seed
  but still keeps the same test captures every time.
- *`StratifiedGroupKFold` from sklearn.* Doesn't combine technique-stratum
  + feature-cluster (D-7) cleanly; rolled our own.
- *Bootstrap test sets.* With 30 positive captures, bootstrap resamples
  collapse to the same handful of captures and don't widen the
  confidence interval meaningfully.

**Source.** Mine. Motivated by empirically observing the variance and
discussing what "honest CV" looks like for this dataset shape.

### M-8. Feature-cluster stratum refinement, gated by `MIN_CLUSTER_SIZE`

**Context.** Capture-level stratification by primary LOTL technique
already keeps every fold's test set balanced by *technique*. But within
one technique (say T1218) the captures can be heterogeneous — mshta
samples, regsvr32 samples, control-panel-DLL samples — and random
within-stratum assignment can still send all of one sub-style to train
and the rest to val. Result: model sees mshta in train, gets quizzed on
SyncAppvPublishingServer at val, val PR-AUC drops to noise.

**Choice.** `refine_strata_by_feature_cluster(strata, signatures)` runs
k-means (k = `min(3, max(2, n // 3))`) on the per-capture mean
L2-normalized n-gram signature within each stratum, producing sub-strata
keyed `"T1218_c0"`, `"T1218_c1"`, etc. Strata with fewer than
`MIN_CLUSTER_SIZE` (6) captures are left intact — clustering 2-3 captures
is statistically meaningless, and below MIN_CLUSTER_SIZE the size-2 split
fallback systematically sends captures to test with none to val (see
splitting.py:_stratum_split_sizes).

**Rejected.**
- *Skip clustering entirely.* What the original pipeline did. Causes
  within-technique mode collapse.
- *Lower min_cluster_size (e.g. 4).* Tried — fragments positive strata
  into size-2 sub-clusters, which the split rule then routes all to test
  / none to val. Val pos drops to ~25, test pos ~450, metrics swing
  wildly.
- *Cluster on dense features too.* The n-gram block has 1024 dims and
  dominates feature distance anyway; the dense block contributes mostly
  scale noise. Tried, no metric improvement, complexity added.
- *Hierarchical / agglomerative clustering.* No clear win on 226-capture
  strata; k-means is faster and produces interpretable cluster IDs.

**Source.** Mine.

### M-9. Capture-level evaluation is reported alongside event-level

**Context.** The model scores per-event but is consumed per-capture in the
cascade (the LLM tier receives a capture's max-scoring event, not all
events). Event-level metrics over-weight long captures (LSASS dumps with
200 events) and treat each event as an independent draw — but a SOC sees
one capture, not 200 independent events.

**Choice.** `evaluate_capture_level(y_true_events, y_score_events,
capture_ids)` groups events by `capture_id`, takes the max score per
capture as its score and max label as its label, then runs the same
`evaluate()` pipeline on the resulting capture-level vectors. Both reports
are produced per fold and aggregated across folds.

Max-aggregation matches operational reality: a capture is malicious if it
*contains* a malicious-looking event, not if its mean event is malicious.
Mean would dilute a single sharp positive across a long benign tail.

**Rejected.**
- *Event-level only.* Treats each event as IID, which they aren't.
- *Capture-level only.* Loses the per-event diagnostic and disconnects
  from how the model is trained.
- *Mean aggregator.* Wrong semantics for this cascade.
- *Quantile aggregator (e.g. 95th percentile of event scores).* More
  robust to single noisy event but adds a tunable parameter; max is
  simpler and matches the alerting model.

**Source.** Mine.

### M-10. Three-tier cascade: YARA → ML → LLM+RAG

**Context.** Operating a single-model LOTL detector at SOC-grade precision
needs much more positive data than the public corpora provide. But a
cascade — cheap fast filter → ML triage → expensive LLM final pass —
sidesteps that constraint by letting each tier do only what it's good at.

**Choice.** The model in this repo is **Tier 2** of a cascade:

- *Tier 1: YARA rules* at precision ≈ 0.99999 (essentially zero FPs). Cheap
  signature matches catch the obvious stuff.
- *Tier 2: ML model* (this repo). Triages events that pass YARA, producing
  a ranked candidate stream.
- *Tier 3: LLM + RAG* over known LOTL attacks. Final precision pass +
  natural-language alert rationale.

The ML tier's *job* is to compress the post-YARA event stream so the LLM
tier only sees the top K% by score. This shapes the entire evaluation
strategy:

- Primary metric: **ROC-AUC** + **recall at top K%** (ranking quality).
- Secondary diagnostic: precision floors (could we autopilot at p95?).
- Threshold strategy: **top-K%**, not a fixed score cutoff. Self-calibrates
  across retrainings and distribution shifts.

**Rejected.**
- *Single-tier ML alerter.* Requires p95+ at deployment recall — not
  feasible with current dataset size (precision_at_p95 = 0.60 ± 0.49,
  i.e. half the folds can't even hit p95).
- *Skip ML, run LLM on all post-YARA events.* Infeasible cost — LLM
  inference is ~$0.01–$0.10 per call vs ~$0 for XGBoost; daily per-host
  volumes would be $100–$1000.
- *Skip YARA, use ML as Tier 1.* Loses the precision-99999 shortcut on
  signatured attacks; wastes the cheapest tier.

**Source.** User design decision (architecture context), informing the
metric/evaluation choices in M-4, M-6, M-7, M-9. Recorded as a project
memory so future sessions don't reach for single-tier precision targets
by default.

## Tooling

### T-1. `uv` for Python package management

**Context.** Pinned reproducibility for a thesis project.

**Choice.** `uv` (already preferred by the user) with
`requires-python = ">=3.11"` and explicit minimum versions in
`pyproject.toml`.

**Rejected.**
- *`pip + requirements.txt`.* Slower, no lockfile by default.
- *Poetry.* Heavier; uv is faster and the user already uses it.

**Source.** User preference (stored as a memory).

### T-2. MLflow for experiment tracking, not TensorBoard / wandb

**Context.** Comparing runs across hyperparams, dataset stacks, and label
rules is the main use case; TensorBoard's strength is per-step training
curves only.

**Choice.** MLflow with autolog (`mlflow.xgboost.autolog()`) + manual
`log_params` / `log_metrics` for data composition and the eval report.
Local file backend at `data/mlruns/`.

**Rejected.**
- *TensorBoard.* Per-run scalars only; weak experiment comparison.
- *wandb.* Hosted UI; thesis prefers self-hosted.

**Source.** User chose MLflow when asked.

### T-3. `omerbenamram/evtx` (`evtx_dump`) for EVTX conversion

**Context.** EVTX-ATTACK-SAMPLES ships native EVTX (BinXML); we need JSONL
for our loaders.

**Choice.** `cargo install evtx`; `prepare.py` shells out to
`evtx_dump -o jsonl -t 1 -f out.jsonl in.evtx`.

**Rejected.**
- *`python-evtx`.* Brief states it is ~1600× slower.
- *`Get-WinEvent | ConvertTo-Json`.* Nests EventData under a Properties
  array that breaks the Sysmon schema.
- *Chainsaw / Hayabusa.* Both wrap `omerbenamram/evtx`; using the underlying
  tool directly avoids a transitive dep.

**Source.** Brief.

### T-4. Loader dialect plug-in pattern

**Context.** Three corpora, three on-disk shapes. The loader needs to be
trivially extensible (DARPA OpTC and your own VM capture come next).

**Choice.** `_DIALECT_LOADERS` mapping in `loaders.py` keyed by string:
`"agent"`, `"mordor"`, `"attack_data"`, `"evtx"`. Each loader is a generator
yielding `SysmonRecord`s.

**Rejected.**
- *Single auto-detecting loader.* Brittle — schema overlap between mordor
  and agent JSONL is partial.
- *One loader, polymorphic on a class hierarchy.* Over-engineered for four
  dialects.

**Source.** Mine.

### T-5. `manifest.json` written in-place during `prepare.py`

**Context.** Loaders need per-capture metadata (malicious flag + ATT&CK
techniques). Copying the entire dataset into a "prepared" tree would double
disk use.

**Choice.** `prepare.py` walks the cloned trees, reads each corpus's native
manifest (OTRF `dataset.yaml`, attack_data `*_manifest.yml`), and writes
`manifest.json` next to the events. The loader reads `manifest.json`
first.

**Rejected.**
- *Copy everything under `data/prepared/`.* Doubles disk for ~10 GB of data.
- *Reparse native YAML on every loader call.* Slow; also forces `PyYAML` as
  a runtime dep instead of a prepare-time dep.

**Source.** Mine.

### T-6. PyYAML for `prepare.py`, not a hand-rolled parser

**Context.** Both OTRF `dataset.yaml` and attack_data `*_manifest.yml` use
real YAML with nested structures.

**Choice.** Add `pyyaml` to deps; use `yaml.safe_load`.

**Rejected.**
- *Regex out the technique IDs.* Fragile across YAML variants.
- *Add `ruamel.yaml`.* Heavier; we don't need round-trip preservation.

**Source.** Mine.

### T-7. Save model as native XGBoost JSON + MLflow artifact

**Context.** Reproducible loading needs the model in a known format.

**Choice.** `booster.save_model("data/lotl_xgb.json")` (native XGBoost JSON,
version-stable) and `mlflow.log_artifact(...)` to attach the same file to
the run.

**Rejected.**
- *Pickle.* Brittle across XGBoost / scikit-learn / Python versions.
- *MLflow's `mlflow.xgboost.log_model`.* Autolog does this already; we keep
  the native dump as the canonical artifact for downstream consumers (e.g.
  a Rust inference path) that don't speak MLflow.

**Source.** Mine.

## Code structure

### S-1. One module per responsibility

**Context.** Thesis code should be easy to navigate and reuse in chapters.

**Choice.** Eleven modules under `train_utils/`, each ≤ ~300 LOC, one
responsibility (`schema`, `lolbas`, `loaders`, `labeling`, `features`,
`splitting`, `train`, `evaluate`, plus `pipeline` for source
loading/labeling/strata building, `cv` for the K-fold loop + per-fold
MLflow logging, and `tracking` for artifact and feature-importance
helpers). `main.py` is glue only.

**Rejected.**
- *Mega-module.* Common in research code; tanks reuse.
- *Class hierarchy with abstract loaders.* Premature — four loader functions
  are simpler than four classes.

**Source.** Mine.

### S-2. Pure Python data types, no `pandas.DataFrame` in the hot path

**Context.** `pandas` is fine for analysis but adds dtype headaches and
indirection in feature engineering.

**Choice.** `SysmonRecord` dataclass + `scipy.sparse.csr_matrix` for the
final feature matrix. `pandas` is in `pyproject.toml` for ad-hoc analysis
but not imported by the pipeline.

**Rejected.**
- *DataFrame all the way.* Slower for the row-by-row feature pass; harder
  to type-check.

**Source.** Mine.

### S-3. `main.py` has no CLI args; all knobs are constants at the top

**Context.** User asked explicitly: "I don't want a CLI app."

**Choice.** Constants — `SEED`, `SOURCES`, `MAX_DEPTH`, etc. — sit at the
top of `main.py` and are logged to MLflow on every run.

**Rejected.**
- *argparse.* Overkill for a thesis pipeline run by one person.

**Source.** User instruction.
