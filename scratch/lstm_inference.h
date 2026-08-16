#ifndef LSTM_INFERENCE_H
#define LSTM_INFERENCE_H

// =========================================================================
// lstm_inference.h — hand-rolled C++ forward pass for MOBIGUARD's trained
// LSTMAutoencoder (lstm_pipeline/src/lstm_model.py), for LIVE in-sim
// inference (main.tex eq:lstm_hidden, eq:anomaly_score, eq:lstm_detection).
//
// Why hand-rolled instead of LibTorch: no LibTorch C++ SDK is set up on
// this machine (no headers, no waf integration, ABI risk from pip-wheel
// torch .so files) — see PENDING_FIXES.md Fix 17. The model is small
// (2-layer LSTM encoder 7->64->32, 2-layer LSTM decoder 32->64->64 +
// Linear(64->7), ~360KB of weights) and reconstruction-only (fc_cls, the
// unused classification head, is NOT exported/implemented here — nothing
// in the live detection path calls it), so a manual forward pass matching
// PyTorch's nn.LSTM equations exactly is tractable and dependency-free.
//
// PyTorch nn.LSTM (single layer, unidirectional, batch_first) semantics
// this implements exactly:
//   weight_ih_l0: (4*H, input_size), weight_hh_l0: (4*H, H)
//   bias_ih_l0, bias_hh_l0: (4*H,)
//   Gate order in the 4*H rows: [input i | forget f | cell g | output o]
//   i_t = sigmoid(W_ii x_t + b_ii + W_hi h_{t-1} + b_hi)
//   f_t = sigmoid(W_if x_t + b_if + W_hf h_{t-1} + b_hf)
//   g_t = tanh   (W_ig x_t + b_ig + W_hg h_{t-1} + b_hg)
//   o_t = sigmoid(W_io x_t + b_io + W_ho h_{t-1} + b_ho)
//   c_t = f_t * c_{t-1} + i_t * g_t
//   h_t = o_t * tanh(c_t)
//   h_0 = c_0 = 0
// This is standard/canonical LSTM and matches PyTorch's documented
// convention (https://pytorch.org/docs/stable/generated/torch.nn.LSTM.html).
//
// Weight file format: see lstm_pipeline/src/export_weights_cpp.py's module
// docstring for the exact binary layout (magic "MGL1", tensor order, then
// per-RSU thetas + global_theta fallback).
//
// Deliberately has ZERO ns3:: / NS-3 dependencies so it can be compiled
// and validated standalone with plain g++ against a PyTorch reference
// output (lstm_inference_test.cpp) BEFORE being included in routing.cc.
// =========================================================================

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace mglstm {

inline float sigmoidf(float x) { return 1.0f / (1.0f + std::exp(-x)); }

// One nn.LSTM(input_size, hidden_size) layer's weights (single layer,
// unidirectional — matches every LSTM in LSTMAutoencoder).
struct LSTMLayer {
    int input_size  = 0;
    int hidden_size = 0;
    std::vector<float> w_ih;  // (4*hidden_size, input_size), row-major
    std::vector<float> w_hh;  // (4*hidden_size, hidden_size), row-major
    std::vector<float> b_ih;  // (4*hidden_size,)
    std::vector<float> b_hh;  // (4*hidden_size,)
};

struct LinearLayer {
    int in_features  = 0;
    int out_features = 0;
    std::vector<float> w;  // (out_features, in_features), row-major
    std::vector<float> b;  // (out_features,)
};

struct LSTMAutoencoderWeights {
    int n_features = 0;
    int hidden1    = 0;
    int hidden2    = 0;
    LSTMLayer enc1, enc2, dec1, dec2;
    LinearLayer fc_recon;
    std::vector<float> theta;       // per-RSU threshold, indexed 0..n_rsus-1
    float global_theta = 0.0f;      // fallback for out-of-range RSU indices
    std::vector<float> feat_mu;     // Z-score scaler mean, eq:lstm_input feature order
    std::vector<float> feat_std;    // Z-score scaler std,  eq:lstm_input feature order
};

// Applies the SAME Z-score normalisation the model was trained on
// (preprocessor.py's apply_scaler(), fit on benign-only data). Raw features
// MUST be normalised before lstm_encode()/lstm_forward_and_score() — the
// model has never seen unnormalised input and will produce meaningless
// scores otherwise.
inline std::vector<float> lstm_normalize_features(const LSTMAutoencoderWeights& m,
                                                    const std::vector<float>& raw)
{
    // Fix 3 (supervisor, 2026-08-14) added an 11th raw feature
    // (obs_exceeded_dmax). A model checkpoint trained on the OLD 10-feature
    // eq:lstm_input has m.feat_mu.size()==10, and the loop below used to
    // silently stop early, leaving out[10] at its zero-initialised default
    // instead of a real normalised value -- quiet corruption, not a crash,
    // for exactly one run-length until someone notices the score is
    // meaningless. Fail loudly instead: this is expected during the window
    // between this code change landing and the model being retrained on 11
    // features (lstm_pipeline/src/export_weights_cpp.py); if it fires after
    // that retrain, the checkpoint being loaded is stale.
    static bool warned = false;
    if (raw.size() != m.feat_mu.size() && !warned) {
        warned = true;
        std::cerr << "[LSTM-INFER] FATAL: raw feature count (" << raw.size()
                  << ") != loaded model's feature count (" << m.feat_mu.size()
                  << "). Model needs retraining/re-export for the current "
                  << "feature vector (Fix 3, 2026-08-14), or a stale "
                  << "checkpoint is loaded. Refusing to silently zero-pad."
                  << std::endl;
        std::abort();
    }
    std::vector<float> out(raw.size());
    for (size_t i = 0; i < raw.size() && i < m.feat_mu.size(); ++i)
        out[i] = (raw[i] - m.feat_mu[i]) / m.feat_std[i];
    return out;
}

// ── Core: run one LSTM layer over a full input sequence, returning the
// full output sequence (T, hidden_size). For a single-layer unidirectional
// LSTM, PyTorch's "final hidden state" h_n equals out[:, -1, :] — callers
// needing only the final hidden state (encode()'s enc2) just take .back().
inline std::vector<std::vector<float>> lstm_layer_forward(
    const LSTMLayer& L, const std::vector<std::vector<float>>& x)
{
    const int T = (int)x.size();
    const int H = L.hidden_size;
    const int I = L.input_size;

    std::vector<float> h(H, 0.0f), c(H, 0.0f);
    std::vector<std::vector<float>> out(T, std::vector<float>(H, 0.0f));

    for (int t = 0; t < T; ++t)
    {
        std::vector<float> gates(4 * H, 0.0f);
        for (int g = 0; g < 4 * H; ++g)
        {
            float sum = L.b_ih[g] + L.b_hh[g];
            const float* wih_row = &L.w_ih[(size_t)g * I];
            for (int k = 0; k < I; ++k) sum += wih_row[k] * x[t][k];
            const float* whh_row = &L.w_hh[(size_t)g * H];
            for (int k = 0; k < H; ++k) sum += whh_row[k] * h[k];
            gates[g] = sum;
        }

        for (int j = 0; j < H; ++j)
        {
            float i_g = sigmoidf(gates[j]);
            float f_g = sigmoidf(gates[H + j]);
            float g_g = std::tanh(gates[2 * H + j]);
            float o_g = sigmoidf(gates[3 * H + j]);
            c[j] = f_g * c[j] + i_g * g_g;
            h[j] = o_g * std::tanh(c[j]);
        }
        out[t] = h;
    }
    return out;
}

inline std::vector<float> linear_forward(const LinearLayer& L, const std::vector<float>& x)
{
    std::vector<float> y(L.out_features, 0.0f);
    for (int o = 0; o < L.out_features; ++o)
    {
        float sum = L.b[o];
        const float* w_row = &L.w[(size_t)o * L.in_features];
        for (int k = 0; k < L.in_features; ++k) sum += w_row[k] * x[k];
        y[o] = sum;
    }
    return y;
}

// encode(): x (T, n_features) -> latent (hidden2,)  [lstm_model.py's encode()]
inline std::vector<float> lstm_encode(const LSTMAutoencoderWeights& m,
                                       const std::vector<std::vector<float>>& x)
{
    auto out1 = lstm_layer_forward(m.enc1, x);   // (T, hidden1)
    auto out2 = lstm_layer_forward(m.enc2, out1); // (T, hidden2)
    return out2.back();                           // final hidden state (hidden2,)
}

// decode(): latent (hidden2,) repeated seq_len times -> x_hat (T, n_features)
// [lstm_model.py's decode()]
inline std::vector<std::vector<float>> lstm_decode(const LSTMAutoencoderWeights& m,
                                                     const std::vector<float>& latent,
                                                     int seq_len)
{
    std::vector<std::vector<float>> rep(seq_len, latent);  // latent.unsqueeze(1).expand(...)
    auto out1 = lstm_layer_forward(m.dec1, rep);  // (T, hidden1)
    auto out2 = lstm_layer_forward(m.dec2, out1); // (T, hidden1)

    std::vector<std::vector<float>> x_hat(seq_len);
    for (int t = 0; t < seq_len; ++t)
        x_hat[t] = linear_forward(m.fc_recon, out2[t]);  // (n_features,)
    return x_hat;
}

// anomaly_score(): eq:anomaly_score — mean squared reconstruction error
// over (time, features), matching lstm_model.py's
// `((x - x_hat) ** 2).mean(dim=(1, 2))`.
inline float lstm_anomaly_score(const std::vector<std::vector<float>>& x,
                                 const std::vector<std::vector<float>>& x_hat)
{
    const int T = (int)x.size();
    const int F = T > 0 ? (int)x[0].size() : 0;
    double sum = 0.0;
    for (int t = 0; t < T; ++t)
        for (int f = 0; f < F; ++f)
        {
            double d = (double)x[t][f] - (double)x_hat[t][f];
            sum += d * d;
        }
    return (T * F > 0) ? (float)(sum / (double)(T * F)) : 0.0f;
}

// Full forward pass: x (T, n_features) -> (x_hat, anomaly_score).
inline float lstm_forward_and_score(const LSTMAutoencoderWeights& m,
                                     const std::vector<std::vector<float>>& x,
                                     std::vector<std::vector<float>>* x_hat_out = nullptr)
{
    auto latent = lstm_encode(m, x);
    auto x_hat  = lstm_decode(m, latent, (int)x.size());
    if (x_hat_out) *x_hat_out = x_hat;
    return lstm_anomaly_score(x, x_hat);
}

// ── eq:theta_adapt — online warm-up threshold adaptation ────────────────────
//
// main.tex:3425 specifies:
//     theta^(k)_adapted = max( theta^(k),  mu_warmup^(k) + z * sigma_warmup^(k) )
// with z = 3.5, mu/sigma taken from anomaly scores observed during a 30 s
// warm-up window at RSU r_k, and the max() ensuring the threshold is only ever
// RAISED, never lowered by a thin or noisy warm-up sample.
//
// WHY THIS WAS ADDED (2026-08-07). Commit 77318f5 implemented this adaptation
// in lstm_pipeline/src/evaluator.py ONLY -- the offline scorer -- and never in
// this file, the live in-simulation detector. The reported improvement (A2 FPR
// 2.42% -> 1.00%, A1 0.78% -> 0.40%) was therefore an OFFLINE result that the
// simulator never reproduced: every live run has been deciding with the static
// per-RSU theta baked into lstm_weights_cpp.bin. Measured 2026-08-07 on Q6, the
// live LSTM contributed 828 false positives against 65 true positives.
// It is also a spec-compliance gap, not merely a missed optimisation: the
// thesis defines eq:theta_adapt as part of the detector.
//
// Rationale for the calibration seed being per-run rather than per-deployment:
// theta calibrated on training seeds underestimates the benign tail on a fresh
// mobility realisation (seed-to-seed variance at interior RSUs), which is the
// diagnostic that motivated the equation in the first place.
double LSTM_WARMUP_S = 30.0;   // main.tex: "30-second warm-up window"
double LSTM_THETA_Z  = 3.5;    // main.tex: same Gaussian multiplier as eq:lstm_threshold
uint32_t LSTM_WARMUP_MIN_N = 5; // guard: too thin a sample -> keep base theta

// Per-RSU warm-up accumulators (sized on first use).
static std::vector<uint32_t> g_lstm_warm_n;
static std::vector<double>   g_lstm_warm_sum;
static std::vector<double>   g_lstm_warm_sumsq;
static std::vector<float>    g_lstm_theta_adapted;   // <0 => not yet computed
static std::vector<uint8_t>  g_lstm_warm_done;

inline void lstm_theta_adapt_reset(size_t n_rsus)
{
    g_lstm_warm_n.assign(n_rsus, 0);
    g_lstm_warm_sum.assign(n_rsus, 0.0);
    g_lstm_warm_sumsq.assign(n_rsus, 0.0);
    g_lstm_theta_adapted.assign(n_rsus, -1.0f);
    g_lstm_warm_done.assign(n_rsus, 0);
}

// True while RSU rsu_idx is still inside its warm-up window. main.tex: "Warm-up
// windows are excluded from all FPR and DR computations" -- exposed so the
// evaluation path can honour that; it does NOT suppress the detector.
inline bool lstm_in_warmup(double t_now) { return t_now < LSTM_WARMUP_S; }

// D_LSTM (eq:lstm_detection): binary detection flag for RSU `rsu_idx`.
// During warm-up the base theta is used and the score is accumulated; at the
// first evaluation after the window closes, theta_adapted is computed once and
// used from then on.
// theta_used (supervisor Fix 2, 2026-08-14): optional out-param returning
// the EFFECTIVE per-RSU theta this call decided against (post warm-up
// adaptation, matching g_lstm_theta_adapted exactly) — so a caller wanting a
// higher-confidence tier (e.g. score > 2*theta_used) compares against the
// same threshold this function actually used, not a separately recomputed
// (and potentially stale/adaptation-unaware) one. Default nullptr, so every
// existing call site is unaffected.
inline bool lstm_detect(const LSTMAutoencoderWeights& m, uint32_t rsu_idx,
                        float score, double t_now, float* theta_used = nullptr)
{
    const float base = (rsu_idx < m.theta.size()) ? m.theta[rsu_idx] : m.global_theta;

    if (rsu_idx >= g_lstm_warm_n.size())          // not initialised -> base only
    {
        if (theta_used) *theta_used = base;
        return score > base;
    }

    if (lstm_in_warmup(t_now))
    {
        g_lstm_warm_n[rsu_idx]     += 1;
        g_lstm_warm_sum[rsu_idx]   += (double)score;
        g_lstm_warm_sumsq[rsu_idx] += (double)score * (double)score;
        if (theta_used) *theta_used = base;
        return score > base;                       // decide with base during warm-up
    }

    if (!g_lstm_warm_done[rsu_idx])
    {
        g_lstm_warm_done[rsu_idx] = 1;
        const uint32_t n = g_lstm_warm_n[rsu_idx];
        float theta = base;
        if (n >= LSTM_WARMUP_MIN_N)
        {
            const double mu  = g_lstm_warm_sum[rsu_idx] / (double)n;
            const double var = (g_lstm_warm_sumsq[rsu_idx] / (double)n) - mu * mu;
            const double sd  = (var > 0.0) ? std::sqrt(var) : 0.0;
            const float  cand = (float)(mu + LSTM_THETA_Z * sd);
            if (cand > theta) theta = cand;        // max(): never lower it
        }
        g_lstm_theta_adapted[rsu_idx] = theta;
    }

    const float theta = (g_lstm_theta_adapted[rsu_idx] >= 0.0f)
                      ? g_lstm_theta_adapted[rsu_idx] : base;
    if (theta_used) *theta_used = theta;
    return score > theta;
}

// ── Weight file loader — see export_weights_cpp.py for the exact binary
// layout this must match byte-for-byte.
inline bool load_lstm_weights(const std::string& path, LSTMAutoencoderWeights& out,
                               std::string* err = nullptr)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
    {
        if (err) *err = "cannot open " + path;
        return false;
    }

    char magic[4];
    f.read(magic, 4);
    if (std::memcmp(magic, "MGL1", 4) != 0)
    {
        if (err) *err = "bad magic in " + path;
        return false;
    }

    uint32_t n_rsus, hidden1, hidden2, n_features;
    f.read(reinterpret_cast<char*>(&n_rsus),     sizeof(uint32_t));
    f.read(reinterpret_cast<char*>(&hidden1),    sizeof(uint32_t));
    f.read(reinterpret_cast<char*>(&hidden2),    sizeof(uint32_t));
    f.read(reinterpret_cast<char*>(&n_features), sizeof(uint32_t));

    out.n_features = (int)n_features;
    out.hidden1    = (int)hidden1;
    out.hidden2    = (int)hidden2;

    auto read_vec = [&](std::vector<float>& v, size_t n) {
        v.resize(n);
        f.read(reinterpret_cast<char*>(v.data()), (std::streamsize)(n * sizeof(float)));
    };

    auto read_lstm_layer = [&](LSTMLayer& L, int input_size, int hidden_size) {
        L.input_size  = input_size;
        L.hidden_size = hidden_size;
        read_vec(L.w_ih, (size_t)4 * hidden_size * input_size);
        read_vec(L.w_hh, (size_t)4 * hidden_size * hidden_size);
        read_vec(L.b_ih, (size_t)4 * hidden_size);
        read_vec(L.b_hh, (size_t)4 * hidden_size);
    };

    read_lstm_layer(out.enc1, out.n_features, out.hidden1);
    read_lstm_layer(out.enc2, out.hidden1,    out.hidden2);
    read_lstm_layer(out.dec1, out.hidden2,    out.hidden1);
    read_lstm_layer(out.dec2, out.hidden1,    out.hidden1);

    out.fc_recon.in_features  = out.hidden1;
    out.fc_recon.out_features = out.n_features;
    read_vec(out.fc_recon.w, (size_t)out.n_features * out.hidden1);
    read_vec(out.fc_recon.b, (size_t)out.n_features);

    read_vec(out.theta, n_rsus);
    f.read(reinterpret_cast<char*>(&out.global_theta), sizeof(float));
    read_vec(out.feat_mu,  n_features);
    read_vec(out.feat_std, n_features);

    if (!f)
    {
        if (err) *err = "truncated/short read on " + path;
        return false;
    }
    return true;
}

}  // namespace mglstm

#endif  // LSTM_INFERENCE_H
