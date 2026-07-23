// lstm_inference_test.cpp — standalone numerical-parity validation for
// lstm_inference.h against lstm_pipeline/src/gen_cpp_validation_case.py's
// PyTorch reference output. Zero NS-3 dependencies — compile directly:
//
//   g++ -O2 -std=c++17 lstm_inference_test.cpp -o /tmp/lstm_test
//   /tmp/lstm_test <path-to-lstm_weights_cpp.bin> <path-to-validation_case.bin>
//
// Exits 0 and prints PASS if the hand-rolled forward pass matches PyTorch's
// within tolerance; exits 1 and prints PASS/FAIL detail otherwise. This is
// the checkpoint gate before lstm_inference.h is ever included in
// routing.cc / wired into the live simulation (see PENDING_FIXES.md Fix 17).

#include "lstm_inference.h"
#include <cstdio>
#include <cstdlib>

using namespace mglstm;

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::fprintf(stderr, "usage: %s <weights.bin> <validation_case.bin>\n", argv[0]);
        return 2;
    }

    LSTMAutoencoderWeights model;
    std::string err;
    if (!load_lstm_weights(argv[1], model, &err))
    {
        std::fprintf(stderr, "FAIL: load_lstm_weights: %s\n", err.c_str());
        return 1;
    }
    std::printf("Loaded weights: n_features=%d hidden1=%d hidden2=%d n_rsus_theta=%zu global_theta=%.6f\n",
                model.n_features, model.hidden1, model.hidden2, model.theta.size(), model.global_theta);

    std::ifstream vf(argv[2], std::ios::binary);
    if (!vf.is_open())
    {
        std::fprintf(stderr, "FAIL: cannot open %s\n", argv[2]);
        return 1;
    }
    char magic[4];
    vf.read(magic, 4);
    if (std::memcmp(magic, "MGV1", 4) != 0)
    {
        std::fprintf(stderr, "FAIL: bad magic in validation case\n");
        return 1;
    }
    uint32_t window, n_features;
    vf.read(reinterpret_cast<char*>(&window),     sizeof(uint32_t));
    vf.read(reinterpret_cast<char*>(&n_features),  sizeof(uint32_t));

    std::vector<std::vector<float>> x(window, std::vector<float>(n_features));
    for (uint32_t t = 0; t < window; ++t)
        vf.read(reinterpret_cast<char*>(x[t].data()), n_features * sizeof(float));

    std::vector<std::vector<float>> x_hat_ref(window, std::vector<float>(n_features));
    for (uint32_t t = 0; t < window; ++t)
        vf.read(reinterpret_cast<char*>(x_hat_ref[t].data()), n_features * sizeof(float));

    float anomaly_ref = 0.0f;
    vf.read(reinterpret_cast<char*>(&anomaly_ref), sizeof(float));

    if (!vf)
    {
        std::fprintf(stderr, "FAIL: truncated validation case\n");
        return 1;
    }

    // Normalisation parity check (independent of the validation_case.bin
    // reconstruction test above, which operates in already-normalised
    // space) — cross-checked by hand against Python's (raw-mu)/std for
    // the same raw vector.
    {
        std::vector<float> raw   = {0.0025f, 2.0f, 0.05f, 1.0f, 0.0f, 15.0f, 9.5f};
        std::vector<float> expected = {1.2666517f, 2.0f, 4.6224618f, 1.0f, 0.0f, 0.4240047f, 0.4206752f};
        auto norm = lstm_normalize_features(model, raw);
        float max_norm_diff = 0.0f;
        for (size_t i = 0; i < expected.size(); ++i)
            max_norm_diff = std::max(max_norm_diff, std::fabs(norm[i] - expected[i]));
        std::printf("normalize_features max diff vs Python reference = %.8g\n", max_norm_diff);
        if (max_norm_diff > 1e-4f)
        {
            std::fprintf(stderr, "FAIL: normalization mismatch\n");
            return 1;
        }
    }

    std::vector<std::vector<float>> x_hat_cpp;
    float anomaly_cpp = lstm_forward_and_score(model, x, &x_hat_cpp);

    std::printf("anomaly_score: PyTorch=%.8f  C++=%.8f  abs_diff=%.8g\n",
                anomaly_ref, anomaly_cpp, std::fabs(anomaly_ref - anomaly_cpp));

    float max_recon_diff = 0.0f;
    for (uint32_t t = 0; t < window; ++t)
        for (uint32_t f = 0; f < n_features; ++f)
        {
            float d = std::fabs(x_hat_ref[t][f] - x_hat_cpp[t][f]);
            if (d > max_recon_diff) max_recon_diff = d;
        }
    std::printf("max |x_hat_ref - x_hat_cpp| over all (t,f) = %.8g\n", max_recon_diff);

    // float32 forward passes through several matmuls; allow a small
    // tolerance for accumulated rounding-order differences between
    // PyTorch's BLAS-backed matmul and this header's naive loops.
    const float TOL = 1e-3f;
    bool pass = (max_recon_diff < TOL) && (std::fabs(anomaly_ref - anomaly_cpp) < TOL);

    std::printf("\n%s (tolerance=%.0e)\n", pass ? "PASS" : "FAIL", TOL);
    return pass ? 0 : 1;
}
