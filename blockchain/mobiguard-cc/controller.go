package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Controller registry and trust management
// Implements §3.4.11: Multi-Controller Zero-Trust Architecture
// Equations: 3.49 (Ctrusted), 3.50 (trust update), 3.52 (SC.Revoke)
// -----------------------------------------------------------------------

// RegisterController adds a new SDVN controller to the blockchain
// registry with an initial trust score of 1.0 (10000 basis points).
// Latitude and longitude are stored for distance-based RSU assignment
// (Eq 3.51 / 3.53). RSUs are stationary so controller positions are
// also fixed — registered once, never updated.
//
// RSU-only (write). In the real deployment this would be called during
// network initialization before any simulation run.
func (c *MobiguardContract) RegisterController(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
	latStr string,
	lngStr string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := keyPrefixController + controllerId

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("controller %s is already registered", controllerId)
	}

	lat, lng, err := parseLatLng(latStr, lngStr)
	if err != nil {
		return err
	}

	record := ControllerRecord{
		DocType:      "controller",
		ControllerId: controllerId,
		Status:       ControllerTrusted,
		TrustScore:   initialCtrlTrustScore,
		Latitude:     lat,
		Longitude:    lng,
		RegisteredAt: timestamp,
		LastUpdate:   timestamp,
	}

	return putState(ctx, key, record)
}

// UpdateControllerTrust applies a trust score update for a controller
// per Eq 3.50. success=true applies reward +Δr, success=false applies
// penalty -Δp. If the resulting score drops below defaultCtrlTrustMin,
// SC.Revoke fires automatically (Eq 3.52).
//
// RSU-only (write). Called directly or via SubmitConflictEvidence
// when conflict evidence quorum is reached.
func (c *MobiguardContract) UpdateControllerTrust(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
	success bool,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}
	return applyControllerTrustUpdate(ctx, controllerId, success, timestamp)
}

// applyControllerTrustUpdate is the internal engine for controller
// trust updates — mirrors applyTrustUpdate for nodes but operates on
// ControllerRecord assets and triggers SC.Revoke instead of quarantine.
func applyControllerTrustUpdate(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
	success bool,
	timestamp int64,
) error {
	key := keyPrefixController + controllerId

	var record ControllerRecord
	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("controller %s is not registered", controllerId)
	}
	if err := getState(ctx, key, &record); err != nil {
		return err
	}

	// Already revoked controllers continue to be monitored but
	// cannot recover to trusted status via this function — only
	// an explicit admin reinstatement would do so (future work).
	if success {
		record.TrustScore += defaultCtrlTrustReward
		if record.TrustScore > trustScoreMax {
			record.TrustScore = trustScoreMax
		}
	} else {
		record.TrustScore -= defaultCtrlTrustPenalty
		if record.TrustScore < trustScoreMin {
			record.TrustScore = trustScoreMin
		}
	}
	record.LastUpdate = timestamp

	// SC.Revoke(ci) — Eq 3.52: if trust drops below T_ctrl_min and
	// controller is still trusted, revoke it and trigger failover.
	if record.TrustScore < defaultCtrlTrustMin &&
		record.Status == ControllerTrusted {
		record.Status = ControllerRevoked
		record.RevokedAt = timestamp

		// Persist revocation first so triggerFailoverAll sees the
		// updated status when it reads controller records.
		if err := putState(ctx, key, record); err != nil {
			return err
		}

		// NEW: emit revocation event for off-chain listeners
		ctx.GetStub().SetEvent("ControllerRevoked", []byte(controllerId))

		// Eq 3.53: automatically reassign all RSUs that were assigned
		// to this now-revoked controller.
		return triggerFailoverAll(ctx, record.ControllerId, timestamp)
	}

	// DEBUG: emit score update event
	eventData := fmt.Sprintf("ctrl=%s score=%d success=%v", controllerId, record.TrustScore, success)
	ctx.GetStub().SetEvent("TrustUpdated", []byte(eventData))

	return putState(ctx, key, record)
}

// SubmitConflictEvidence records that an RSU detected an unauthorized
// FlowMod from a specific controller (funauth=1, Eq 3.44 → Eq 3.50).
//
// One ConflictEvidence record is created per (controllerId, reportingRsuId)
// pair — a single RSU cannot submit multiple reports for the same
// controller, preventing a compromised RSU from framing a legitimate
// controller alone.
//
// When the total count of distinct RSU reports for a controller reaches
// conflictEvidenceQuorum (f+1=2), the controller's trust score is
// automatically penalized (Eq 3.50). If the penalty causes the score
// to cross T_ctrl_min, SC.Revoke fires (Eq 3.52) and
// TriggerFailoverAll reassigns all affected RSUs (Eq 3.53).
//
// RSU-only (write).
func (c *MobiguardContract) SubmitConflictEvidence(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
	flowModHash string,
	timestamp int64,
) error {
	rsuID, err := requireRSU(ctx)
	if err != nil {
		return err
	}

	// Verify controller is registered.
	ctrlKey := keyPrefixController + controllerId
	exists, err := assetExists(ctx, ctrlKey)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("controller %s is not registered", controllerId)
	}

	// One report per (controller, RSU) pair.
	evidenceKey := keyPrefixConflict + controllerId + ":" + rsuID
	alreadyExists, err := assetExists(ctx, evidenceKey)
	if err != nil {
		return err
	}
	if alreadyExists {
		return fmt.Errorf(
			"RSU %s has already submitted conflict evidence against controller %s",
			rsuID, controllerId,
		)
	}

	// Count existing evidence BEFORE writing ours.
	// GetStateByRange (used by countConflictEvidence) reads committed
	// CouchDB state only — it cannot see PutState writes from the current
	// transaction. Counting first and adding 1 gives the correct post-write
	// total without relying on phantom reads.
	count, err := countConflictEvidence(ctx, controllerId)
	if err != nil {
		return err
	}
	count++ // include the record we are about to write

	// Record the conflict evidence.
	evidence := ConflictEvidence{
		DocType:        "conflict",
		ControllerId:   controllerId,
		ReportingRsuId: rsuID,
		FlowModHash:    flowModHash,
		Timestamp:      timestamp,
	}
	if err := putState(ctx, evidenceKey, evidence); err != nil {
		return err
	}

	// Eq 3.50: when conflict evidence >= f+1, penalize controller trust.
	// SC.Revoke and TriggerFailoverAll fire automatically inside
	// applyControllerTrustUpdate when score crosses T_ctrl_min (Eq 3.52/3.53).
	if count >= conflictEvidenceQuorum {
		if err := applyControllerTrustUpdate(
			ctx, controllerId, false, timestamp,
		); err != nil {
			return err
		}
	}

	return nil
}

// GetTrustedControllers returns the current trusted controller set
// Ctrusted(t) — all controllers with status="trusted" and trust score
// >= T_ctrl_min (Eq 3.49).
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetTrustedControllers(
	ctx contractapi.TransactionContextInterface,
) ([]*ControllerRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixController)
	if err != nil {
		return nil, err
	}

	trusted := make([]*ControllerRecord, 0)
	for _, data := range results {
		var record ControllerRecord
		if err := unmarshalAsset(data, &record); err != nil {
			return nil, err
		}
		if record.TrustScore >= defaultCtrlTrustMin {
			trusted = append(trusted, &record)
		}
	}
	return trusted, nil
}

// GetAllControllers returns all registered controllers regardless of
// status — useful for audit and monitoring.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAllControllers(
	ctx contractapi.TransactionContextInterface,
) ([]*ControllerRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixController)
	if err != nil {
		return nil, err
	}

	controllers := make([]*ControllerRecord, 0)
	for _, data := range results {
		var record ControllerRecord
		if err := unmarshalAsset(data, &record); err != nil {
			return nil, err
		}
		controllers = append(controllers, &record)
	}
	return controllers, nil
}

// GetControllerStatus returns the full record for a single controller.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetControllerStatus(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
) (*ControllerRecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixController + controllerId
	var record ControllerRecord
	if err := getState(ctx, key, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// GetConflictEvidenceCount returns how many distinct RSUs have submitted
// conflict evidence against a controller. Useful for monitoring how
// close a controller is to the penalty quorum.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetConflictEvidenceCount(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
) (int, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return 0, err
	}
	return countConflictEvidence(ctx, controllerId)
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

// countConflictEvidence counts distinct RSU conflict reports for a
// controller by ranging over conflict:{controllerId}: prefix.
func countConflictEvidence(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
) (int, error) {
	prefix := keyPrefixConflict + controllerId + ":"
	results, err := getStateByPrefix(ctx, prefix)
	if err != nil {
		return 0, err
	}
	return len(results), nil
}

// isControllerRevoked returns true if the controller's current status
// is ControllerRevoked.
func isControllerRevoked(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
) (bool, error) {
	key := keyPrefixController + controllerId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	var record ControllerRecord
	if err := getState(ctx, key, &record); err != nil {
		return false, err
	}
	return record.Status == ControllerRevoked, nil
}

// parseLatLng parses latitude and longitude from string parameters.
// Fabric chaincode function parameters are always strings — floats
// must be passed as strings and parsed here.
func parseLatLng(latStr, lngStr string) (float64, float64, error) {
	var lat, lng float64
	if _, err := fmt.Sscanf(
		strings.TrimSpace(latStr), "%f", &lat,
	); err != nil {
		return 0, 0, fmt.Errorf(
			"invalid latitude %q: %v", latStr, err,
		)
	}
	if _, err := fmt.Sscanf(
		strings.TrimSpace(lngStr), "%f", &lng,
	); err != nil {
		return 0, 0, fmt.Errorf(
			"invalid longitude %q: %v", lngStr, err,
		)
	}
	if lat < -90 || lat > 90 {
		return 0, 0, fmt.Errorf(
			"latitude %f out of range [-90, 90]", lat,
		)
	}
	if lng < -180 || lng > 180 {
		return 0, 0, fmt.Errorf(
			"longitude %f out of range [-180, 180]", lng,
		)
	}
	return lat, lng, nil
}
