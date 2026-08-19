"""
finetune_a1a2.py — Supervisor Fix B, fine-tune step (2026-08-19).

Freezes all LSTM weights except the final reconstruction layer (fc_recon),
fine-tunes 10 epochs on the RELABELED A1/A2 benign windows only (preprocessor.py
was just re-run with the corrected Delta_max=50ms exceedance threshold --
see that file's Fix B comment for why the label population changed). The
model is a reconstruction autoencoder trained only on benign (y==0) windows;
previously-mislabeled attack-active A1/A2 windows (delay 50-293ms, wrongly
counted benign under the old p99 threshold) are now correctly excluded from
that training population, which is the actual mechanism by which relabeling
improves detection -- the model stops learning to reconstruct genuine attack
patterns as "normal".

Does NOT touch fed_summary.json / models/global.pt / lstm_weights_cpp.bin --
writes a separate checkpoint (models/global_finetuned_a1a2.pt) so the
baseline stays comparable until this is validated and someone decides to
promote it.
"""
import json
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

EPOCHS = 10
LR = 1e-3
BATCH = 256
FINE_TUNE_VARIANTS = {1, 2}


def main():
    print("Loading current global model …")
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])

    # Freeze everything except fc_recon (the final reconstruction layer).
    frozen, trainable = [], []
    for name, p in model.named_parameters():
        if name.startswith("fc_recon"):
            p.requires_grad = True
            trainable.append(name)
        else:
            p.requires_grad = False
            frozen.append(name)
    print(f"Frozen ({len(frozen)} tensors): {frozen[:3]} ...")
    print(f"Trainable ({len(trainable)} tensors): {trainable}")

    X_tr   = np.load(PRE / "train_X.npy")
    y_tr   = np.load(PRE / "train_y.npy")
    meta_tr = np.load(PRE / "train_meta.npy")
    av_tr  = meta_tr[:, 1].astype(int)

    # Reconstruction training population: BENIGN (y==0) windows from A1/A2
    # runs only, using the freshly relabeled y_tr (previously-mislabeled
    # attack-active windows are now correctly excluded here).
    mask = (y_tr == 0) & np.isin(av_tr, list(FINE_TUNE_VARIANTS))
    X_ft = X_tr[mask]
    print(f"\nFine-tune population: {len(X_ft)} benign A1/A2 windows "
          f"(out of {int((av_tr == list(FINE_TUNE_VARIANTS)[0]).sum() + (av_tr == list(FINE_TUNE_VARIANTS)[1]).sum())} total A1/A2 train windows)")

    opt = torch.optim.Adam([p for p in model.parameters() if p.requires_grad], lr=LR)
    loss_fn = nn.MSELoss()

    n = len(X_ft)
    idx = np.arange(n)
    model.train()
    for epoch in range(1, EPOCHS + 1):
        np.random.shuffle(idx)
        total_loss = 0.0
        for i in range(0, n, BATCH):
            b = idx[i:i + BATCH]
            xb = torch.from_numpy(X_ft[b]).float().to(DEVICE)
            opt.zero_grad()
            x_hat, _ = model(xb)
            loss = loss_fn(x_hat, xb)
            loss.backward()
            opt.step()
            total_loss += loss.item() * len(b)
        print(f"  epoch {epoch}/{EPOCHS}: loss={total_loss / n:.6f}")

    model.eval()
    out_path = MODEL_DIR / "global_finetuned_a1a2.pt"
    torch.save({"weights": model.state_dict(),
                "note": "Fix B fine-tune (2026-08-19): frozen enc1/enc2/dec1/dec2, "
                        "trained fc_recon only, 10 epochs, benign A1/A2 windows "
                        "relabeled with Delta_max=50ms exceedance threshold"},
               out_path)
    print(f"\nSaved -> {out_path}")


if __name__ == "__main__":
    main()
