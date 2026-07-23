"""
gen_cpp_validation_case.py — Generates a fixed test input + the reference
PyTorch output (reconstruction + anomaly score) for validating the
hand-rolled C++ forward pass (scratch/lstm_inference.h) against the real
model, BEFORE wiring it into the live NS-3 simulation.

Writes validation_case.bin: a flat float32 file the standalone C++
validation harness reads directly (see scratch/lstm_inference_test.cpp).

Format:
  magic        : 4 bytes = b"MGV1"
  window       : uint32  (= 10, matches preprocessor.py's WINDOW)
  n_features   : uint32  (= 7)
  x            : window * n_features float32 (row-major: [t][f])
  x_hat_ref    : window * n_features float32 (PyTorch's reconstruction)
  anomaly_ref  : 1 float32 (PyTorch's anomaly_score for this x)

Usage:
  python3 gen_cpp_validation_case.py
"""

import struct
from pathlib import Path

import numpy as np
import torch

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO / "lstm_pipeline" / "models"
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

    out_path = REPO / "lstm_pipeline" / "validation_case.bin"
    with open(out_path, "wb") as f:
        f.write(b"MGV1")
        f.write(struct.pack("<II", WINDOW, N_FEATURES))
        f.write(x_np.astype("<f4").tobytes())
        f.write(x_hat_np.tobytes())
        f.write(struct.pack("<f", anomaly_val))

    print(f"x[0] = {x_np[0]}")
    print(f"x_hat[0] (PyTorch) = {x_hat_np[0]}")
    print(f"anomaly_score (PyTorch) = {anomaly_val:.8f}")
    print(f"\nWrote validation case -> {out_path}")


if __name__ == "__main__":
    main()
