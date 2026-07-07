# SFTO-Guard Benchmark Pipeline

Offline reproduction of SFTO-Guard (Tang et al., 2023) as a benchmark
for your SDVN TCAM-exhaustion defense system.

## Setup

```bash
cd src
pip install -r ../requirements.txt
```

## File layout

```
sfto_pipeline/
├── src/
│   ├── run_pipeline.py         # offline entry point (train + random-split eval)
│   ├── realtime_detect.py      # streaming/causal replay of an already-trained model
│   ├── loader.py                # CSV loader + snapshot labeling
│   ├── features.py              # per-rule features + 42-feature aggregation
│   ├── selection.py             # SHAP selection (sweep 1-10)
│   ├── detector.py              # LightGBM training + evaluation
│   ├── reporting.py             # save results + print summary
│   └── test_existing_models.py  # cross-dataset generalization check
├── results/                     # one subfolder per trained run (model + metrics)
│   ├── routing_attack3/, routing_attack4/, v2/, v3/, v4/, sumo/, ...
└── requirements.txt
```

Trained models under `results/*/lgbm_detector.pkl` were produced by
`run_pipeline.py` runs against ns-3 sim output that lives outside this repo
(regenerated per machine/run, not committed).

## Usage

All commands below are run from `sfto_pipeline/src/`.

### Full run (with SHAP selection re-run on your data — recommended)
```bash
python run_pipeline.py \
  --baseline  /path/to/tcam_snapshots_baseline.csv \
  --attack    /path/to/tcam_snapshots_attack3.csv \
  --attack_start_time 10 \
  --output    ../results/attack3_new/
```

### Skip SHAP and use the paper's original 8 features directly
```bash
python run_pipeline.py \
  --baseline  /path/to/tcam_snapshots_baseline.csv \
  --attack    /path/to/tcam_snapshots_attack3.csv \
  --attack_start_time 10 \
  --output    ../results/attack3_paper_features/ \
  --skip_shap
```

### Attack 4 (data plane)
```bash
python run_pipeline.py \
  --baseline  /path/to/tcam_snapshots_baseline.csv \
  --attack    /path/to/tcam_snapshots_attack4.csv \
  --attack_start_time 10 \
  --output    ../results/attack4_new/
```

### Real-time / streaming replay (causal, no train/test leakage)
`run_pipeline.py` trains and scores on a random 75/25 split of one dataset —
it tells you whether the model *can* separate attack from normal, not
whether it would fire promptly on live traffic. `realtime_detect.py` takes
an already-trained model and replays a CSV **in time order**, reporting
detection latency and any pre-attack false alarms:
```bash
python realtime_detect.py \
  --model    ../results/routing_attack3/lgbm_detector.pkl \
  --metrics  ../results/routing_attack3/metrics.json \
  --stream   /path/to/tcam_snapshots_attack3.csv \
  --attack_start_time 10 \
  --output   ../results/realtime_attack3/
```
Always replay against a run/seed the model was **not trained on** (e.g. a
different rng seed or scenario) — scoring the same file the model was
fit on will make even a broken model look perfect, since ~75% of it was
literally memorized during training.

## Output files

| File | Contents |
|------|----------|
| `metrics.json` | acc/prec/recall/F1/AUC + selected features |
| `classification_report.txt` | per-class breakdown |
| `benchmark_table.csv` | single-row table for your paper |
| `shap_ranking.csv` | all 42 features ranked by SHAP value |
| `feature_sweep.csv` | F1/acc/prec at each step of 1-10 sweep |
| `feature_comparison_vs_paper.csv` | your top-8 vs. paper's top-8 |
| `lgbm_detector.pkl` | trained model (joblib) |
| `feature_matrix.csv` | 42-feature matrix with labels |

## What the numbers mean for your paper

- **High F1 (>95%)** at fixed density: confirms the pipeline works
  and SFTO-Guard can detect TCAM exhaustion in simple conditions.
  This is the expected "deceptively good" baseline result.

- **Compare two runs**:
  1. `--skip_shap` (paper's 8 features) vs. full SHAP re-run.
     The delta shows how much feature transfer matters.
  2. Later (after SUMO): re-run at multiple vehicle densities.
     SFTO-Guard's static threshold will false-positive at high density;
     your density-normalized detector (Eq. 3.3) won't.
     That gap is your headline result.

- **Coverage table** (in your evaluation chapter):
  SFTO-Guard covers attacks 3 & 4 only.
  Your system covers attacks 1-8.
  This single table is your strongest argument.

## Class imbalance note

Your attack3.csv has ~85% malicious rows (50,900 / 59,716).
The pipeline uses `class_weight='balanced'` in LightGBM to handle this.
The snapshot-level imbalance (label=0 vs label=1 snapshots) is the
relevant one for the detector — check your loader output for those counts.
