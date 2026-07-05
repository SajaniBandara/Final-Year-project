package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 3: Trust scores (Eq 3.46)
// Asset 4: Quarantine / peer lifecycle (Eq 3.47 + supervisor three-state
//          model: active -> demoted -> removed)
// -----------------------------------------------------------------------

// UpdateTrust applies a trust score update for nodeId per Eq 3.46.
// Public RSU-callable entry point; delegates to applyTrustUpdate.
//
// success = true  corresponds to (VerifyAgg=1 AND pi=valid) in Eq 3.46 /
//                 Algorithm 5 (BTMM): reward +Δr.
// success = false corresponds to any verification failure: penalty -Δp.
//
// RSU-only (write).
func (c *MobiguardContract) UpdateTrust(ctx contractapi.TransactionContextInterface, nodeId string, success bool, timestamp int64) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}
	return applyTrustUpdate(ctx, nodeId, success, timestamp)
}

// applyTrustUpdate is the shared internal engine implementing Eq 3.46
// and the three-state peer lifecycle. Called by:
//   - UpdateTrust (direct RSU call)
//   - LogDetection (automatic penalty side-effect)
//   - SubmitAlert at 2f+1 quorum (automatic penalty side-effect)
//
// The caller must have already passed requireRSU before reaching here.
//
// Three-state lifecycle (supervisor instruction):
//
//  score >= T_demote (3000): active full peer, no quarantine record
//  T_remove <= score < T_demote: QuarantineDemoted (peer->client)
//    - node still monitored, trust updates continue
//    - excluded from peer selection (QueryPeerSelection)
//    - LiftQuarantine can restore to active
//  score < T_remove (1000) while already demoted: QuarantineRemoved
//    - writes for this node are blocked (checked at entry)
//    - removal is permanent (LiftQuarantine rejected)
//
// Write-block for removed nodes: checked first, before any state read,
// so removed nodes accumulate no further ledger state.
func applyTrustUpdate(ctx contractapi.TransactionContextInterface, nodeId string, success bool, timestamp int64) error {
	// Check if node is already removed — if so, block all writes.
	qKey := keyPrefixQuarantine + nodeId
	qExists, err := assetExists(ctx, qKey)
	if err != nil {
		return err
	}
	if qExists {
		var existing QuarantineRecord
		if err := getState(ctx, qKey, &existing); err != nil {
			return err
		}
		if existing.Status == QuarantineRemoved {
			return fmt.Errorf("node %s has been removed from the system; all writes are blocked", nodeId)
		}
	}

	// Read or initialise trust score.
	tKey := keyPrefixTrust + nodeId
	var trust TrustScore
	tExists, err := assetExists(ctx, tKey)
	if err != nil {
		return err
	}
	if tExists {
		if err := getState(ctx, tKey, &trust); err != nil {
			return err
		}
	} else {
		trust = TrustScore{
			DocType: "trust",
			NodeId:  nodeId,
			Score:   initialTrustScore,
		}
	}

	// Apply Eq 3.46: reward or penalty, clamped to [0, 10000].
	if success {
		trust.Score += defaultTrustReward
		if trust.Score > trustScoreMax {
			trust.Score = trustScoreMax
		}
	} else {
		trust.Score -= defaultTrustPenalty
		if trust.Score < trustScoreMin {
			trust.Score = trustScoreMin
		}
	}
	trust.LastUpdate = timestamp

	if err := putState(ctx, tKey, trust); err != nil {
		return err
	}

	// Three-state lifecycle transitions.
	return applyLifecycleTransition(ctx, nodeId, trust.Score, timestamp, qExists)
}

// applyLifecycleTransition evaluates the new trust score against the
// demotion/removal thresholds and updates the QuarantineRecord
// accordingly. Separated from applyTrustUpdate for readability.
func applyLifecycleTransition(ctx contractapi.TransactionContextInterface, nodeId string, score int, timestamp int64, qRecordExists bool) error {
	qKey := keyPrefixQuarantine + nodeId

	if score >= defaultTrustDemote {
		// Score is healthy — no quarantine action needed.
		// Note: we do NOT auto-lift here. A demoted node with a
		// recovering score stays demoted until an RSU explicitly calls
		// LiftQuarantine. This prevents oscillation from transient
		// score recoveries re-admitting a suspect peer automatically.
		return nil
	}

	if !qRecordExists {
		// First time dropping below T_demote: create demotion record.
		record := QuarantineRecord{
			DocType:   "quarantine",
			NodeId:    nodeId,
			Status:    QuarantineDemoted,
			DemotedAt: timestamp,
			Timestamp: timestamp,
		}
		return putState(ctx, qKey, record)
	}

	// A quarantine record already exists — read it to check current state.
	var record QuarantineRecord
	if err := getState(ctx, qKey, &record); err != nil {
		return err
	}

	// If already removed, should never reach here (blocked at entry of
	// applyTrustUpdate), but guard defensively.
	if record.Status == QuarantineRemoved {
		return nil
	}

	// If score drops below T_remove while already demoted: escalate to removed.
	if record.Status == QuarantineDemoted && score < defaultTrustRemove {
		record.Status = QuarantineRemoved
		record.RemovedAt = timestamp
		record.Timestamp = timestamp
		return putState(ctx, qKey, record)
	}

	// If previously lifted but score has dropped again below T_demote:
	// re-demote.
	if record.Status == QuarantineLifted {
		record.Status = QuarantineDemoted
		record.DemotedAt = timestamp // update demotion timestamp
		record.LiftedAt = record.LiftedAt // preserve last lift timestamp
		record.Timestamp = timestamp
		return putState(ctx, qKey, record)
	}

	// Already demoted and score is between T_remove and T_demote: no
	// status change, but Timestamp is NOT updated here to avoid
	// spurious writes — the demotion record reflects original demotion
	// time, which is more informative for audit purposes.
	return nil
}

// -----------------------------------------------------------------------
// Public trust query functions
// -----------------------------------------------------------------------

// QueryTrust returns the current trust score for nodeId. If no record
// exists yet, returns the default initial score (10000) without creating
// a ledger entry. Controller's read path per Table 3.3.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryTrust(ctx contractapi.TransactionContextInterface, nodeId string) (*TrustScore, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixTrust + nodeId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &TrustScore{
			DocType: "trust",
			NodeId:  nodeId,
			Score:   initialTrustScore,
		}, nil
	}

	var trust TrustScore
	if err := getState(ctx, key, &trust); err != nil {
		return nil, err
	}
	return &trust, nil
}

// GetAllTrustScores returns all recorded trust scores.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAllTrustScores(ctx contractapi.TransactionContextInterface) ([]*TrustScore, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixTrust)
	if err != nil {
		return nil, err
	}

	scores := make([]*TrustScore, 0, len(results))
	for _, data := range results {
		var trust TrustScore
		if err := unmarshalAsset(data, &trust); err != nil {
			return nil, err
		}
		scores = append(scores, &trust)
	}
	return scores, nil
}

// -----------------------------------------------------------------------
// Quarantine / peer lifecycle management
// -----------------------------------------------------------------------

// LiftQuarantine reinstates a demoted node to active peer status. This
// is a manual RSU decision — automatic lifting does NOT happen even if
// the trust score recovers above T_demote, to prevent suspect nodes from
// oscillating back into the peer set without explicit RSU review.
//
// Rules:
//   - Only QuarantineDemoted nodes can be lifted.
//   - QuarantineRemoved nodes cannot be lifted (ejection is permanent).
//   - Does NOT reset the trust score. If score is still below T_demote,
//     the next applyTrustUpdate(false) will immediately re-demote.
//
// RSU-only (write).
func (c *MobiguardContract) LiftQuarantine(ctx contractapi.TransactionContextInterface, nodeId string, timestamp int64) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := keyPrefixQuarantine + nodeId

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no quarantine record found for node %s; node is currently active", nodeId)
	}

	var record QuarantineRecord
	if err := getState(ctx, key, &record); err != nil {
		return err
	}

	switch record.Status {
	case QuarantineRemoved:
		return fmt.Errorf("node %s has been removed from the system; removal is permanent and cannot be lifted", nodeId)
	case QuarantineLifted:
		return fmt.Errorf("node %s quarantine is already lifted", nodeId)
	case QuarantineDemoted:
		record.Status = QuarantineLifted
		record.LiftedAt = timestamp
		record.Timestamp = timestamp
		return putState(ctx, key, record)
	default:
		return fmt.Errorf("unknown quarantine status %q for node %s", record.Status, nodeId)
	}
}

// GetQuarantineRecord returns the full quarantine record for a node, or
// nil if the node has no quarantine history (i.e. is currently active
// with no past demotions).
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetQuarantineRecord(ctx contractapi.TransactionContextInterface, nodeId string) (*QuarantineRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixQuarantine + nodeId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil // active node, no quarantine history
	}

	var record QuarantineRecord
	if err := getState(ctx, key, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// QueryQuarantineList returns all nodes currently in QuarantineDemoted
// status (the "client" tier — active but not peer-eligible).
// Controller's read path for the active demotion list per Table 3.3.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryQuarantineList(ctx contractapi.TransactionContextInterface) ([]*QuarantineRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixQuarantine)
	if err != nil {
		return nil, err
	}

	demoted := make([]*QuarantineRecord, 0)
	for _, data := range results {
		var record QuarantineRecord
		if err := unmarshalAsset(data, &record); err != nil {
			return nil, err
		}
		if record.Status == QuarantineDemoted {
			demoted = append(demoted, &record)
		}
	}
	return demoted, nil
}

// QueryRemovedList returns all nodes in QuarantineRemoved status
// (permanently ejected from the system).
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryRemovedList(ctx contractapi.TransactionContextInterface) ([]*QuarantineRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixQuarantine)
	if err != nil {
		return nil, err
	}

	removed := make([]*QuarantineRecord, 0)
	for _, data := range results {
		var record QuarantineRecord
		if err := unmarshalAsset(data, &record); err != nil {
			return nil, err
		}
		if record.Status == QuarantineRemoved {
			removed = append(removed, &record)
		}
	}
	return removed, nil
}
