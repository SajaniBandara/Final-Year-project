#!/bin/bash
# Resume the round-10 retrain from A6 after the 09:28 abort.
# A1-A4 succeeded. A5 (evaluator.py) crashed on MOBIGUARD append contamination in
# its rule-based M4-M8 section; no later step reads its output, so it is skipped
# here and handled separately. Every later gate is unchanged from orchestrate.sh.
set -u
P=/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project
LP=$P/lstm_pipeline; SRC=$LP/src
NS3=/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35
R=$NS3/results_routing
O=/tmp/claude-1001/-home-sdvn-hidden-attacks-ns3-g13-g13-project-repo-Final-Year-project/725a44bf-987f-4a71-837a-5932c950e25b/scratchpad/orch
G=$O/gates; mkdir -p "$G"
PY=python3

log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*"; }
gate(){ touch "$G/$1"; log "GATE $1"; }
die(){ log "FATAL: $*"; gate A_FAIL; exit 1; }
step(){ local name=$1 cwd=$2; shift 2
  log "START $name: $*"
  ( cd "$cwd" && "$@" ) > "$O/$name.log" 2>&1; local rc=$?
  log "END   $name rc=$rc"; return $rc; }

log "RESUME from A6. A1-A4 succeeded at 09:21-09:28; A5 evaluator skipped (MOBIGUARD append contamination; no downstream dependency)."

# The A1-A4 outputs must come from THIS retrain (original start.stamp), not an older one.
for x in models/global.pt models/global_clshead_indep.pt fed_summary.json scaler_params.json preprocessed/train_X.npy; do
  [ "$LP/$x" -nt "$O/start.stamp" ] || die "$x is not from this retrain"
done
log "A1-A4 outputs verified fresh"

# ===== PHASE A (remainder) ===================================================
# CPU on purpose. calibrate_hc_theta.py pushes all ~102k benign validation windows through
# the model in ONE batch (~5.5 GiB), and another project's service (smdac_llm
# serve_detector.py) holds ~21 GiB of the GPU; the 09:33 attempt died with CUDA OOM.
# Same calculation on CPU, and the in-sim C++ inference runs on CPU anyway.
step A6_calibrate_hc "$SRC" env CUDA_VISIBLE_DEVICES= $PY calibrate_hc_theta.py || die "calibrate_hc_theta failed"
[ "$LP/hc_theta.json" -nt "$O/start.stamp" ] || die "hc_theta.json was not regenerated"

NEWHC=$($PY -c "import json;print(json.load(open('$LP/hc_theta.json'))['theta_hc'])") || die "cannot read theta_hc"
log "new theta_hc = $NEWHC"
$PY - "$P/scratch/lstm_logger.h" "$NEWHC" <<'PYEOF' || die "failed to patch LSTM_HC_THETA"
import re, sys
p, val = sys.argv[1], float(sys.argv[2])
s = open(p).read()
pat = re.compile(r'^(static float\s+LSTM_HC_THETA\s*=\s*)[-0-9.eE]+f;.*$', re.M)
new, n = pat.subn(lambda m: f"{m.group(1)}{val:.6f}f;  // hc_theta.json, p99.9 benign, 2026-09-11 round-10 retrain (frozen head)", s)
assert n == 1, f"expected exactly 1 match, got {n}"
open(p, "w").write(new); print("patched LSTM_HC_THETA ->", val)
PYEOF
log "rebuilding ns-3 (nothing is running at this point)"
( cd "$NS3" && env -u CXXFLAGS ./waf build ) > "$O/A7_rebuild.log" 2>&1 || die "ns-3 rebuild failed"
grep -q "finished successfully" "$O/A7_rebuild.log" || die "rebuild did not report success"
gate A_PASS

# ===== PHASE B: non-LSTM Q runs, on the final binary ========================
nohup bash "$O/q_chain.sh" > "$O/q_chain.log" 2>&1 &
log "Q chain launched (pid $!)"

# ===== PHASE C: export + C++/Python numerical verification ==================
CK=$LP/models/global_clshead_indep.pt
nf_ok(){ $PY - "$LP/lstm_weights_cpp.bin" <<'PYEOF'
import struct, sys
b = open(sys.argv[1], "rb").read(20)
magic = b[:4]; n_rsus, h1, h2, nf = struct.unpack("<4I", b[4:20])
print(f"bin header: magic={magic} n_rsus={n_rsus} hidden={h1}/{h2} n_features={nf}")
sys.exit(0 if (magic == b"MGL1" and nf == 11 and n_rsus == 64) else 4)
PYEOF
}
if step C1_export  "$SRC" $PY export_weights_cpp.py --ckpt "$CK" \
   && [ "$LP/lstm_weights_cpp.bin" -nt "$O/start.stamp" ] && nf_ok >> "$O/C1_export.log" 2>&1 \
   && step C2_valcase "$SRC" $PY gen_cpp_validation_case.py --ckpt "$CK" \
   && step C3_compile "$P/scratch" g++ -O2 -std=c++17 lstm_inference_test.cpp -o "$O/lstm_test" \
   && step C4_verify  "$P/scratch" "$O/lstm_test" ../lstm_pipeline/lstm_weights_cpp.bin ../lstm_pipeline/validation_case.bin \
   && grep -q "PASS" "$O/C4_verify.log" && ! grep -q "FAIL" "$O/C4_verify.log"; then
  gate C_PASS
else
  log "PHASE C FAILED; see $O/C*.log. Q3/Q6 will NOT run; non-LSTM chain continues."
  gate C_FAIL; exit 0
fi

# ===== PHASE D: in-sim classifier threshold calibration ======================
FIX="--N_Controllers=4 --N_RSUs=64 --N_Vehicles=200 --architecture=3 --enable_detector_windows=1 --enable_lstm_cls=1 --maxspeed=150 --mobility_scenario=0 --routing_test=false --simTime=300 --sim_run=1 --use_sumo_mobility=1"
Q6F="--g_disable_s1_s2=0 --g_disable_s3_s4=0 --g_disable_s5_s6=0 --g_disable_s7_s8=0 --g_disable_ranom=0 --enable_lstm_inference=1 --enable_witness_mechanism=1 --disable_crypto=0 --g_disable_btmm_trust=0"
pids=""
for s in 1 2 3; do
  ( cd "$NS3" && ./waf --run-no-build "scratch/routing/routing $FIX $Q6F --attack_percentage=0 --training=1 --run_tag=INSIMCAL --sim_seed=$s" ) > "$O/D1_insimcal_s$s.log" 2>&1 &
  pids="$pids $!"
done
log "INSIMCAL benign runs launched (seeds 1-3):$pids"
wait $pids

dfail(){ log "PHASE D FAILED: $*"; gate D_FAIL; exit 0; }
for s in 1 2 3; do
  f=$R/lstm_training/RSU_10/Attack0_0_seed${s}_INSIMCAL.csv
  [ -f "$f" ] || dfail "missing $f"
  rows=$(( $(wc -l < "$f") - 1 )); [ "$rows" -ge 295 ] || dfail "seed $s only $rows cycles"
  [ "$rows" -le 300 ] || dfail "seed $s has $rows rows (>300): appended onto an older INSIMCAL file"
  nz=$(awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i=="lstm_anomaly_score") c=i} NR>1 && $c!="0" && $c!=""{n++} END{print n+0}' "$f")
  [ "$nz" -gt 0 ] || dfail "seed $s has no in-sim LSTM scores (inference did not load?)"
  log "INSIMCAL seed $s: $rows cycles, $nz scored rows"
done
step D2_calibrate "$SRC" $PY calibrate_cls_theta_insim.py --tag INSIMCAL --target-fpr 0.01 --out ../cls_theta_insim.json \
  || dfail "calibrate_cls_theta_insim failed"
[ "$LP/cls_theta_insim.json" -nt "$O/start.stamp" ] || dfail "cls_theta_insim.json not regenerated"
$PY -c "import json,sys; d=json.load(open('$LP/cls_theta_insim.json')); sys.exit(0 if len(d['per_rsu_threshold'])==64 else 5)" \
  || dfail "cls_theta_insim.json does not hold 64 RSU thresholds"
cp -a "$LP/cls_theta_insim.json" "$LP/cls_theta.json"
log "cls_theta.json <- in-sim thresholds"

MV=$R/lstm_training_INSIMCAL_20260911
for d in "$R"/lstm_training/RSU_*; do
  mkdir -p "$MV/$(basename "$d")"
  mv "$d"/*_INSIMCAL.csv "$MV/$(basename "$d")/" 2>/dev/null
done
left=$(find "$R/lstm_training" -name '*_INSIMCAL.csv' | wc -l)
[ "$left" -eq 0 ] || dfail "$left INSIMCAL files still in lstm_training/"
log "INSIMCAL CSVs moved to $MV"
gate D_PASS
log "Resume phases A6-D complete; Q chain handles Q3/Q6."
