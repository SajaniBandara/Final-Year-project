"""
gen_cpp_validation_case.py — Generates a fixed test input + the reference
PyTorch output (reconstruction + anomaly score) for validating the
hand-rolled C++ forward pass (scratch/lstm_inference.h) against the real
model, BEFORE wiring it into the live NS-3 simulation.

Writes validation_case.bin: a flat float32 file the standalone C++
validation harness reads directly (see scratch/lstm_inference_test.cpp).

Format (MGV2):
  magic        : 4 bytes = b"MGV2"
  window       : uint32  (= 10, matches preprocessor.py's WINDOW)
  n_features   : uint32  (= 11, since 2026-08-14 supervisor Fix 3's
                          delta_t_exceeded addition -- was 10 before.
                          Derived from N_FEATURES, not hardcoded here.)
  x            : window * n_features float32 (row-major: [t][f])
  x_hat_ref    : window * n_features float32 (PyTorch's reconstruction)
  anomaly_ref  : 1 float32 (PyTorch's anomaly_score for this x)
  raw          : n_features float32 (fixed raw, unnormalised feature vector)
  norm_ref     : n_features float32 (PyTorch's (raw-mu)/std using scaler_params.json)

Usage:
  python3 gen_cpp_validation_case.py
"""

import json
import struct
from pathlib import Path

import numpy as np
import torch

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO / "lstm_pipeline" / "models"
SCALER_PATH = REPO / "lstm_pipeline" / "scaler_params.json"
WINDOW = 10


def main():
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location="cpu", weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES)
    model.load_state_dict(ckpt["weights"])
    model.eval()

    # Fixed, reproducible test input (not random per-run — a validation
    # case must be identical every time it's regenerated).
    rng = np.random.RandomState(42)
    x_np = rng.uniform(-2.0, 2.0, size=(WINDOW, N_FEATURES)).astype("float32")

    x = torch.from_numpy(x_np).unsqueeze(0)  # (1, W, F)
    with torch.no_grad():
        x_hat, _ = model(x)
        anomaly = ((x - x_hat) ** 2).mean(dim=(1, 2))

    x_hat_np = x_hat.squeeze(0).numpy().astype("<f4")
    anomaly_val = float(anomaly.item())

    sc = json.load(open(SCALER_PATH))
    mu = np.array([sc["mu"][f] for f in sc["features"]], dtype=np.float64)
    std = np.array([sc["std"][f] for f in sc["features"]], dtype=np.float64)
    assert len(sc["features"]) == N_FEATURES, \
        f"scaler has {len(sc['features'])} features, model has {N_FEATURES}"

    # Fixed raw probe vector — same RNG discipline as x_np: reproducible,
    # not random per-run. Values are in raw feature units, NOT normalised.
    raw = rng.uniform(0.0, 2.0, size=N_FEATURES).astype("float32")
    norm_ref = ((raw.astype(np.float64) - mu) / std).astype("<f4")

    out_path = REPO / "lstm_pipeline" / "validation_case.bin"
    with open(out_path, "wb") as f:
        f.write(b"MGV2")
        f.write(struct.pack("<II", WINDOW, N_FEATURES))
        f.write(x_np.astype("<f4").tobytes())
        f.write(x_hat_np.tobytes())
        f.write(struct.pack("<f", anomaly_val))
        f.write(raw.astype("<f4").tobytes())
        f.write(norm_ref.tobytes())

    print(f"x[0] = {x_np[0]}")
    print(f"x_hat[0] (PyTorch) = {x_hat_np[0]}")
    print(f"anomaly_score (PyTorch) = {anomaly_val:.8f}")
    print(f"\nWrote validation case -> {out_path}")


if __name__ == "__main__":
    main()
