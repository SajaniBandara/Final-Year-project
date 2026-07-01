package main

// =============================================================================
// sim_params.go -- Placeholder simulation parameter constants
//
// Supervisor instruction: "Need to have simulation settings for
// unimplemented things at least in placeholder level for now."
//
// All values here are PLACEHOLDERS. They are named after the report's
// equations and §4.2 simulation settings table (Table 4.1). Each is
// marked with its source equation and the condition under which the
// real value will be determined (SUMO calibration, LSTM training, etc.).
//
// These constants are NOT currently used by chaincode logic -- they
// document the intended parameterization for when the corresponding
// ns-3 / SUMO / federated LSTM components are implemented (Phases 3+).
// =============================================================================

const (
	// -----------------------------------------------------------------------
	// S1: Selective Time Delay, Control Plane (Eq 3.5 / 3.15-3.17)
	// -----------------------------------------------------------------------

	// S1KSigma: number of standard deviations above baseline delay that
	// triggers S1 flag (Eq 3.5: delta_p > delta_bar_r + k*sigma_r).
	// Placeholder: k=3 (standard 3-sigma threshold). Real value fitted
	// from offline SUMO mobility traces per §4.2.2.
	S1KSigma = 3

	// S1EwmaBeta: EWMA forgetting factor beta in [0,1] for running
	// variance estimate sigma_r(t) (Eq 3.16). Placeholder: 0.9
	// (retains 90% historical weight). Real value from SUMO calibration.
	S1EwmaBeta = 0.9 // NOTE: float -- not usable as Go const in arithmetic;
	// store as int scaled x100 if needed in chaincode (90 = 0.90).

	// -----------------------------------------------------------------------
	// S2: Selective Time Delay, Data Plane (Eq 3.6)
	// -----------------------------------------------------------------------

	// S2DeltaMaxMs: maximum allowable forwarding delay Delta_max in
	// milliseconds (Eq 3.6: t_recv - t_fwd > Delta_max AND pi_delay = perp).
	// Placeholder: 50 ms (half the 100 ms safety-critical bound).
	// Real value: calibrated against DSRC propagation + processing budget.
	S2DeltaMaxMs = 50

	// -----------------------------------------------------------------------
	// S3: Slow TCAM Exhaustion, Control Plane (Eq 3.7 / 3.18)
	// -----------------------------------------------------------------------

	// S3LambdaThresh: density-normalised anomalous FlowMod rate threshold
	// lambda_thresh (Eq 3.7 / 3.18). Placeholder: 10 FlowMods/s above
	// expected legitimate rate. Real value from SUMO vehicle density traces.
	S3LambdaThresh = 10

	// S3UtcamThresh: TCAM utilisation threshold U_thresh (Eq 3.7/3.18).
	// Placeholder: 80% (0-100 scale). Real value from ns-3 TCAM model.
	S3UtcamThresh = 80

	// -----------------------------------------------------------------------
	// S4: Slow TCAM Exhaustion, Data Plane (Eq 3.8)
	// -----------------------------------------------------------------------

	// S4LambdaPIThresh: per-vehicle PACKET_IN flood rate threshold
	// lambda_PI_thresh (Eq 3.8). Placeholder: 5 PACKET_IN/s from a
	// single vehicle. Real value from ns-3 baseline measurement.
	S4LambdaPIThresh = 5

	// S4UtcamThresh: TCAM utilisation threshold for S4 (same interpretation
	// as S3UtcamThresh, may differ after calibration). Placeholder: 80%.
	S4UtcamThresh = 80

	// -----------------------------------------------------------------------
	// S5: Active Hidden Forwarding, Control Plane (Eq 3.9)
	// -----------------------------------------------------------------------
	// S5 detection relies on: (a) unauthorized FlowMod flag (Eq 3.44,
	// already implemented in QueryUnauthorizedFlowMod), (b) BLS
	// verification failure on fabricated copy, (c) ZKP hop-legitimacy
	// failure. No additional scalar thresholds -- fully determined by
	// cryptographic pass/fail outcomes from the ns-3 crypto layer.
	// Placeholder: no numeric constants needed for S5 at chaincode level.

	// -----------------------------------------------------------------------
	// S6: Active Hidden Forwarding, Data Plane (Eq 3.10)
	// -----------------------------------------------------------------------
	// S6 detection relies on: duplicate msg_id across two destinations
	// within observation window W, BLS failure, ZKP hop failure.

	// S6ObservationWindowS: witness observation window W in seconds
	// (Eq 3.10, 3.20). Placeholder: 10 s (matching LSTM sequence window
	// per §4.2.3 and the 9-22 s RSU zone residence time from §3.3.3).
	S6ObservationWindowS = 10

	// -----------------------------------------------------------------------
	// S7: Passive Hidden Forwarding, Control Plane (Eq 3.11)
	// -----------------------------------------------------------------------

	// S7VolRateThresh: volume rate threshold epsilon_vol for detecting
	// unexpected traffic to unauthorized destination d' (Eq 3.11:
	// d/dt Vol(d',t) > epsilon_vol). Placeholder: 5 packets/s.
	// Real value from baseline traffic characterization.
	S7VolRateThresh = 5

	// -----------------------------------------------------------------------
	// S8: Passive Hidden Forwarding, Data Plane (Eq 3.12)
	// -----------------------------------------------------------------------
	// S8 primary detection is witness-based (Eq 3.20-3.24); ZKP hop
	// failure is corroborating only. No additional scalar thresholds
	// beyond S6ObservationWindowS and witnessAlertQuorum (already in
	// types.go). No new constants needed here.

	// -----------------------------------------------------------------------
	// Mobility baseline parameters (Eq 3.15, §4.2.1)
	// -----------------------------------------------------------------------

	// MobilityDelta0Ms: static propagation baseline delay delta_0 in ms
	// (Eq 3.15: delta_bar_r = delta_0 + alpha_rho*rho + alpha_v/v_bar).
	// Placeholder: 1 ms (DSRC 270 m at speed-of-light ~0.9 us, plus
	// typical processing ~1 ms). Real value from ns-3 baseline run.
	MobilityDelta0Ms = 1

	// MobilityAlphaRho: density sensitivity coefficient alpha_rho (Eq 3.15),
	// units: ms per vehicle/km. Placeholder: 0 (treated as int; real
	// float value fitted from SUMO offline traces per §4.2.2).
	// PLACEHOLDER -- real value is a float, store as 0 until calibrated.
	MobilityAlphaRho = 0

	// MobilityAlphaV: speed sensitivity coefficient alpha_v (Eq 3.15),
	// units: ms*km/h. Placeholder: 0. Real float value from SUMO traces.
	MobilityAlphaV = 0

	// -----------------------------------------------------------------------
	// Federated LSTM parameters (§4.2.3, Eq 3.33-3.38)
	// -----------------------------------------------------------------------
	// These are ns-3/Python-side parameters documented here for
	// cross-reference. Chaincode only sees the hash of submitted weights
	// (CommitModelHash / VerifyModelHash), not the LSTM internals.

	// LSTMSequenceWindowS: sliding window size in seconds for LSTM input
	// sequences (§4.2.3). Value: 10 s.
	LSTMSequenceWindowS = 10

	// LSTMStrideS: stride between consecutive windows in seconds (§4.2.3).
	LSTMStrideS = 5

	// LSTMLayer1Units: hidden units in first LSTM layer (§4.2.3). Value: 64.
	LSTMLayer1Units = 64

	// LSTMLayer2Units: hidden units in second LSTM layer (§4.2.3). Value: 32.
	LSTMLayer2Units = 32

	// FedAvgLocalEpochs: local training epochs per FedAvg round (§4.2.3).
	FedAvgLocalEpochs = 5

	// FedAvgGlobalRounds: total global FedAvg rounds (§4.2.3). Value: 50.
	FedAvgGlobalRounds = 50

	// LSTMDetectionThreshold: anomaly score threshold for binary
	// classification (§4.2.3). Represented as percentage * 100
	// (i.e. 50 = 0.50 sigmoid output threshold).
	LSTMDetectionThresholdPct = 50

	// -----------------------------------------------------------------------
	// Cryptographic layer parameters (§4.2.4, Eq 3.25-3.32)
	// -----------------------------------------------------------------------

	// CryptoBatchSize: BLS aggregate signature batch size in packets
	// (§4.2.4). Value: 50 packets per batch (~1 s aggregation window).
	CryptoBatchSize = 50

	// CryptoBatchBudgetMs: per-batch BLS verification latency budget in
	// ms (§4.2.4). Value: 20 ms, leaving margin within 100 ms bound.
	CryptoBatchBudgetMs = 20

	// -----------------------------------------------------------------------
	// Blockchain / PBFT parameters (§4.2.5, Eq 3.45)
	// -----------------------------------------------------------------------

	// BlockIntervalS: PBFT block commit interval in seconds (§4.2.5).
	// Value: 1 s (aligned with 1 Hz data transmission cycle).
	BlockIntervalS = 1

	// MaxTxPerBlock: maximum transactions per block (§4.2.5). Value: 50.
	MaxTxPerBlock = 50

	// TotalPBFTPeers: total PBFT validating peers (controller + 64 RSUs,
	// §4.2.5). Value: 65.
	TotalPBFTPeers = 65

	// MaxByzantinePeers: maximum Byzantine peers PBFT can tolerate
	// = floor((TotalPBFTPeers - 1) / 3) = floor(64/3) = 21 (§4.2.5).
	MaxByzantinePeers = 21
)
