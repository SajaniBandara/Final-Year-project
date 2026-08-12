"""
lstm_model.py — MOBIGUARD LSTM autoencoder (eq:lstm_hidden, eq:anomaly_score)

Architecture (§Simulation settings):
  Encoder : LSTM(10→64) → LSTM(64→32)   — produces latent h at final step
  Decoder : repeat latent W times → LSTM(32→64) → LSTM(64→10) → Linear(10)
  Score   : A_t = ||x_t − x̂_t||²₂    (eq:anomaly_score, per time-step mean)

N_FEATURES raised 7->10 2026-07-26: d_div, a_tp, r_anom added to
eq:lstm_input (preprocessor.py's FEATURES list is the single source of
truth for column order; this must always match its length).
"""

import hashlib
import numpy as np
import torch
import torch.nn as nn

N_FEATURES = 10
HIDDEN1    = 64
HIDDEN2    = 32
DROPOUT    = 0.2   # Q25: Q30 holdout (seeds 6/7/8) showed 11-15% FPR on the
# trained model vs <1% target, on data the model was never fit/calibrated
# against -- a generalization/overfitting symptom, not a threshold problem.
# Applied between stacked LSTM stages (encoder and decoder), not inside a
# single nn.LSTM's internal gates.


def seed_everything(seed: int = 0) -> None:
    """Make training reproducible so M1/M8 metrics are stable run-to-run.
    Without this, unseeded weight init + batch shuffling gave Delta_poison
    swings of 0.007-0.09 between identical pipeline invocations."""
    import random as _random
    _random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class LSTMAutoencoder(nn.Module):
    def __init__(self, n_features: int = N_FEATURES,
                 hidden1: int = HIDDEN1, hidden2: int = HIDDEN2):
        super().__init__()
        self.n_features = n_features
        self.hidden1    = hidden1
        self.hidden2    = hidden2

        # Encoder — eq:lstm_hidden
        self.enc1 = nn.LSTM(n_features, hidden1, batch_first=True)
        self.enc2 = nn.LSTM(hidden1,    hidden2, batch_first=True)
        self.drop_enc = nn.Dropout(DROPOUT)

        # Decoder (autoencoder reconstruction head — eq:anomaly_score)
        self.dec1 = nn.LSTM(hidden2, hidden1, batch_first=True)
        self.dec2 = nn.LSTM(hidden1, hidden1, batch_first=True)
        self.drop_dec = nn.Dropout(DROPOUT)
        self.fc_recon = nn.Linear(hidden1, n_features)

        # Classification head — FC sigmoid for binary detection (spec §4.1)
        self.fc_cls = nn.Sequential(
            nn.Linear(hidden2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def encode(self, x: torch.Tensor):
        """x: (B, W, F) → latent: (B, hidden2)"""
        out, _ = self.enc1(x)
        out = self.drop_enc(out)
        _, (h, _) = self.enc2(out)
        return h.squeeze(0)                          # (B, hidden2)

    def decode(self, latent: torch.Tensor, seq_len: int):
        """latent: (B, hidden2) → reconstruction: (B, W, F)"""
        rep  = latent.unsqueeze(1).expand(-1, seq_len, -1)
        out, _ = self.dec1(rep)
        out = self.drop_dec(out)
        out, _ = self.dec2(out)
        return self.fc_recon(out)                    # (B, W, F)

    def forward(self, x: torch.Tensor):
        """Returns (x_hat, p_attack): reconstruction + binary attack probability."""
        latent = self.encode(x)
        x_hat  = self.decode(latent, x.size(1))
        p_atk  = self.fc_cls(latent).squeeze(-1)    # (B,)
        return x_hat, p_atk

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """eq:anomaly_score: MSE reconstruction error per sample."""
        x_hat, _ = self(x)
        return ((x - x_hat) ** 2).mean(dim=(1, 2))  # (B,)

    def classify(self, x: torch.Tensor) -> torch.Tensor:
        """Binary attack probability from sigmoid head: (B,) in [0,1]."""
        _, p_atk = self(x)
        return p_atk


def build_model(device: str = "cuda") -> LSTMAutoencoder:
    model = LSTMAutoencoder()
    return model.to(device if torch.cuda.is_available() else "cpu")


def compute_weights_hash(state_dict: dict) -> str:
    """SHA3-512 of flattened weights — BRFA-v2 SC.CommitModelHash / SC.VerifyModelHash (eq:bc_model_verify)."""
    flat = np.concatenate([v.detach().cpu().numpy().ravel() for v in state_dict.values()])
    return hashlib.sha3_512(flat.tobytes()).hexdigest()
