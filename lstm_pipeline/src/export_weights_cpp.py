"""
export_weights_cpp.py — Export a trained LSTMAutoencoder's reconstruction-path
weights (enc1, enc2, dec1, dec2, fc_recon) to a flat binary format for the
hand-rolled C++ forward pass in scratch/lstm_inference.h (live in-sim
inference, main.tex §5039 escalation-to-LSTM work).

fc_cls (the classification head) is NOT exported — it isn't used by
anomaly_score()/D_LSTM (eq:lstm_detection), and was never trained with a
classification loss (reconstruction-only training throughout this project).

Per-RSU thresholds theta^(k) are exported alongside the weights, read from
fed_summary.json's "per_rsu" block (theta already reflects whichever
compute_theta() formula was in effect when fed_aggregator.py last ran — the
hybrid max(Gaussian, P99) threshold as of this export, Fix 15).

Binary format (little-endian, float32 throughout — matches PyTorch's
default dtype, no precision loss from the export):
  magic       : 4 bytes  = b"MGL1" (MobiGuard Lstm export v1)
  n_rsus      : uint32
  hidden1     : uint32   (= 64)
  hidden2     : uint32   (= 32)
  n_features  : uint32   (= 10, since the 2026-07-27 D_div/A_tp/R_anom expansion)
  -- then, in this fixed order, each tensor as raw float32 row-major --
  enc1.weight_ih_l0  (4*hidden1, n_features)
  enc1.weight_hh_l0  (4*hidden1, hidden1)
  enc1.bias_ih_l0    (4*hidden1,)
  enc1.bias_hh_l0    (4*hidden1,)
  enc2.weight_ih_l0  (4*hidden2, hidden1)
  enc2.weight_hh_l0  (4*hidden2, hidden2)
  enc2.bias_ih_l0    (4*hidden2,)
  enc2.bias_hh_l0    (4*hidden2,)
  dec1.weight_ih_l0  (4*hidden1, hidden2)
  dec1.weight_hh_l0  (4*hidden1, hidden1)
  dec1.bias_ih_l0    (4*hidden1,)
  dec1.bias_hh_l0    (4*hidden1,)
  dec2.weight_ih_l0  (4*hidden1, hidden1)
  dec2.weight_hh_l0  (4*hidden1, hidden1)
  dec2.bias_ih_l0    (4*hidden1,)
  dec2.bias_hh_l0    (4*hidden1,)
  fc_recon.weight    (n_features, hidden1)
  fc_recon.bias      (n_features,)
  -- then n_rsus float32 theta values, in RSU-index order 0..n_rsus-1 --
  theta[0..n_rsus-1]
  -- then one float32 global_theta (fallback for RSUs missing from per_rsu) --
  global_theta
  -- then the Z-score scaler (scaler_params.json), n_features each, same
     FEATURES order as eq:lstm_input / TENSOR_ORDER above. Live inference
     MUST apply (x - mu) / std per feature before the forward pass — the
     model was trained entirely on normalised input (preprocessor.py's
     apply_scaler(), fit on benign data only) and will produce meaningless
     scores on raw features. --
  feat_mu[0..n_features-1]
  feat_std[0..n_features-1]

Usage:
  python3 export_weights_cpp.py [--out PATH]
"""

import argparse
import json
import struct
from pathlib import Path

import torch

REPO = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO / "lstm_pipeline" / "models"
FED_SUMMARY = REPO / "lstm_pipeline" / "fed_summary.json"
SCALER_PATH = REPO / "lstm_pipeline" / "scaler_params.json"

TENSOR_ORDER = [
    "enc1.weight_ih_l0", "enc1.weight_hh_l0", "enc1.bias_ih_l0", "enc1.bias_hh_l0",
    "enc2.weight_ih_l0", "enc2.weight_hh_l0", "enc2.bias_ih_l0", "enc2.bias_hh_l0",
    "dec1.weight_ih_l0", "dec1.weight_hh_l0", "dec1.bias_ih_l0", "dec1.bias_hh_l0",
    "dec2.weight_ih_l0", "dec2.weight_hh_l0", "dec2.bias_ih_l0", "dec2.bias_hh_l0",
    "fc_recon.weight", "fc_recon.bias",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "lstm_pipeline" / "lstm_weights_cpp.bin"))
    ap.add_argument("--ckpt", default=str(MODEL_DIR / "global.pt"))
    args = ap.parse_args()

    ckpt = torch.load(args.ckpt, map_location="cpu", weights_only=False)
    sd = ckpt["weights"]

    hidden1 = sd["enc1.weight_ih_l0"].shape[0] // 4
    hidden2 = sd["enc2.weight_ih_l0"].shape[0] // 4
    n_features = sd["enc1.weight_ih_l0"].shape[1]
    print(f"hidden1={hidden1} hidden2={hidden2} n_features={n_features}")

    fed = json.load(open(FED_SUMMARY))
    per_rsu = fed["per_rsu"]
    n_rsus = max(int(k) for k in per_rsu.keys()) + 1
    global_theta = float(fed["global_theta"])
    print(f"n_rsus={n_rsus} (from fed_summary.json's per_rsu, max index + 1) "
          f"global_theta={global_theta:.6f}")

    with open(args.out, "wb") as f:
        f.write(b"MGL1")
        f.write(struct.pack("<IIII", n_rsus, hidden1, hidden2, n_features))

        for name in TENSOR_ORDER:
            arr = sd[name].detach().cpu().numpy().astype("<f4")
            f.write(arr.tobytes())
            print(f"  wrote {name:22s} shape={tuple(arr.shape)} bytes={arr.nbytes}")

        thetas = []
        for r in range(n_rsus):
            entry = per_rsu.get(str(r))
            thetas.append(float(entry["theta"]) if entry is not None else global_theta)
        f.write(struct.pack(f"<{n_rsus}f", *thetas))
        f.write(struct.pack("<f", global_theta))
        print(f"  wrote {n_rsus} per-RSU thetas + 1 global_theta fallback")

        scaler = json.load(open(SCALER_PATH))
        assert scaler["features"] == [
            "delta_t", "lambda_PI", "U_TCAM", "zkp_delay_fail", "zkp_hop_fail", "rho", "v_bar",
            "d_div", "a_tp", "r_anom"
        ], "scaler_params.json feature order must match eq:lstm_input exactly"
        mu  = [scaler["mu"][k]  for k in scaler["features"]]
        std = [scaler["std"][k] for k in scaler["features"]]
        f.write(struct.pack(f"<{n_features}f", *mu))
        f.write(struct.pack(f"<{n_features}f", *std))
        print(f"  wrote scaler: mu={mu}")
        print(f"                std={std}")

    print(f"\nExported -> {args.out} ({Path(args.out).stat().st_size} bytes)")


if __name__ == "__main__":
    main()
