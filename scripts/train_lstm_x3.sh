#!/usr/bin/env bash
# Trains the final LSTM three times offline with different seeds (training noise, supervisor 2026-10-09) and archives each run
# under lstm_pipeline/runs/seed<k>/. Steps 2-4 of pipeline.py (local trainer, federated aggregation + BRFA-v2, evaluator); step 1 was run once.
set -e
cd "$(dirname "$0")/../lstm_pipeline/src"
PY=${PY:-/home/sdvn_hidden_attacks/.pyenv/versions/3.10.14/bin/python}
for k in 1 2 3; do
  echo "=== training seed $k : $(date +%T)"
  export MOBIGUARD_TRAIN_SEED=$k
  $PY pipeline.py --from-step 2 2>&1 | tail -40 > "../runs_seed${k}.log" || true
  mkdir -p ../runs/seed$k
  cp -r ../models ../runs/seed$k/models
  for f in fed_summary.json local_results.json hparams.json evaluation_results.json scaler_params.json; do [ -f ../$f ] && cp ../$f ../runs/seed$k/; done
  echo "=== seed $k done : $(date +%T)"
done
