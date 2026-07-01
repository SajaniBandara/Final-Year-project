package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 6: Witness alerts (Eq 3.20-3.24)
// -----------------------------------------------------------------------

// SubmitAlert records a signed witness alert (alpha_w, Eq 3.22, or
// beta_w, Eq 3.23) for a given packet hash. Per the report, witness
// vehicles submit alpha_w / beta_w "directly on-chain, bypassing any
// RSU" (§3.4.7) — however, per SPEC.md's access-control model (write
// access restricted to RSU identities), this chaincode requires the
// submission to be relayed via an RSU identity. The witnessId parameter
// identifies the originating witness vehicle distinctly from the
// submitting RSU's Fabric identity.
//
// TODO(witness-direct-write): this RSU-relay requirement is a known
// deviation from §3.4.7's "bypassing any RSU" anti-suppression
// guarantee — a single malicious relaying RSU could currently drop a
// witness alert before it reaches the ledger. Acceptable for Phase 2
// since witness logic does not yet exist in ns-3 (blocked on S1-S8 per
// PHASES.md). Revisit when witness-based forwarding verification is
// implemented: either (a) enroll vehicle/witness Fabric identities
// directly (VehicleOrgMSP) so SubmitAlert can accept non-RSU callers, or
// (b) keep RSU-relay but require the bridge to broadcast each alert to
// multiple RSUs so single-RSU suppression doesn't prevent on-chain
// recording.
//
// Key: alert:{packetHash}
//
// If no record exists for packetHash, one is created with alertType and
// suspectNode taken from this first submission. Subsequent calls for the
// same packetHash must use the same alertType and suspectNode (a packet
// hash represents one accusation; mixing dup/non-fwd or suspect nodes
// under the same hash would conflate Eq 3.20 and Eq 3.21 conditions).
//
// witnessId is appended to Alerts[] if not already present, and
// VerifiedCount is incremented accordingly (signedAlert is assumed to
// have been verified — i.e. BLS.Verify(.) = 1 per Eq 3.24 — by the
// calling RSU before submission; this chaincode does not perform BLS
// verification itself).
//
// Once VerifiedCount >= witnessAlertQuorum (2f+1, Eq 3.24), SC.PenalizeTrust
// fires: applyTrustUpdate(suspectNode, success=false) is called exactly
// once (guarded by the Penalized flag), which may in turn trigger
// quarantine (Eq 3.47) if the resulting score falls below T_min.
//
// RSU-only (write).
func (c *MobiguardContract) SubmitAlert(ctx contractapi.TransactionContextInterface, packetHash string, alertType string, suspectNode string, witnessId string, signedAlert string, timestamp int64) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	at := AlertType(alertType)
	if at != AlertDuplication && at != AlertNonForward {
		return fmt.Errorf("type must be %q or %q, got %q", AlertDuplication, AlertNonForward, alertType)
	}

	// Block writes for removed nodes.
	if err := requireNotRemoved(ctx, suspectNode); err != nil {
		return err
	}

	key := keyPrefixAlert + packetHash

	var alert WitnessAlert
	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		if err := getState(ctx, key, &alert); err != nil {
			return err
		}
		if alert.AlertType != at {
			return fmt.Errorf("alert %s already exists with type %q, cannot resubmit as %q", packetHash, alert.AlertType, at)
		}
		if alert.SuspectNode != suspectNode {
			return fmt.Errorf("alert %s already exists with suspect node %q, cannot resubmit with %q", packetHash, alert.SuspectNode, suspectNode)
		}
	} else {
		alert = WitnessAlert{
			DocType:     "alert",
			PacketHash:  packetHash,
			AlertType:   at,
			SuspectNode: suspectNode,
			Alerts:      []string{},
		}
	}

	for _, w := range alert.Alerts {
		if w == witnessId {
			return fmt.Errorf("witness %s has already submitted an alert for packet %s", witnessId, packetHash)
		}
	}

	alert.Alerts = append(alert.Alerts, witnessId)
	alert.VerifiedCount = len(alert.Alerts)

	// Persist the alert state first, then apply the penalty if quorum is
	// newly reached. This ordering ensures the alert record reflects the
	// triggering submission even if the trust update were to fail.
	if err := putState(ctx, key, alert); err != nil {
		return err
	}

	// Eq 3.24: SC.PenalizeTrust(v_i) <= |{alpha_w u beta_w : Verify=1}| >= 2f+1
	if alert.VerifiedCount >= witnessAlertQuorum && !alert.Penalized {
		if err := applyTrustUpdate(ctx, alert.SuspectNode, false, timestamp); err != nil {
			return err
		}
		alert.Penalized = true
		if err := putState(ctx, key, alert); err != nil {
			return err
		}
	}

	return nil
}

// GetAlert returns the witness alert record for a given packet hash.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAlert(ctx contractapi.TransactionContextInterface, packetHash string) (*WitnessAlert, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixAlert + packetHash

	var alert WitnessAlert
	if err := getState(ctx, key, &alert); err != nil {
		return nil, err
	}
	return &alert, nil
}

// GetAllAlerts returns all recorded witness alerts.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAllAlerts(ctx contractapi.TransactionContextInterface) ([]*WitnessAlert, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixAlert)
	if err != nil {
		return nil, err
	}

	alerts := make([]*WitnessAlert, 0, len(results))
	for _, data := range results {
		var alert WitnessAlert
		if err := unmarshalAsset(data, &alert); err != nil {
			return nil, err
		}
		alerts = append(alerts, &alert)
	}
	return alerts, nil
}
