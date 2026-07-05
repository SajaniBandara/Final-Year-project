package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 2: Detection events (Eq 3.42)
// -----------------------------------------------------------------------

// LogDetection records a detection event for one of signatures S1-S8
// (Eq 3.42, BC.Write). signatureIdx must be in [1,8].
//
// Key: detect:{suspectNode}:{timestamp}
//
// RSU-only (write). The RsuId field is taken from the caller's identity
// (the writing RSU r_k), not a parameter, so a detection event is always
// attributable to the RSU that observed it.
//
// Write-blocked if suspectNode has QuarantineRemoved status — removed
// nodes are ejected and generate no further ledger state.
func (c *MobiguardContract) LogDetection(ctx contractapi.TransactionContextInterface, suspectNode string, signatureIdx int, timestamp int64, rsuSig string) error {
	rsuID, err := requireRSU(ctx)
	if err != nil {
		return err
	}

	if signatureIdx < 1 || signatureIdx > 8 {
		return fmt.Errorf("signatureIndex must be between 1 and 8 (S1-S8), got %d", signatureIdx)
	}

	// Block writes for removed nodes.
	if err := requireNotRemoved(ctx, suspectNode); err != nil {
		return err
	}

	key := fmt.Sprintf("%s%s:%d", keyPrefixDetection, suspectNode, timestamp)

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("detection event already logged for node %s at timestamp %d", suspectNode, timestamp)
	}

	event := DetectionEvent{
		DocType:      "detection",
		SuspectNode:  suspectNode,
		SignatureIdx: signatureIdx,
		Timestamp:    timestamp,
		RsuId:        rsuID,
		RsuSig:       rsuSig,
	}

	if err := putState(ctx, key, event); err != nil {
		return err
	}

	// A detection event represents a failed verification outcome
	// (Algorithm 5, BTMM: bagg ^ b_pi = false branch), so it always
	// applies a trust penalty to the suspect node and may trigger
	// quarantine (Eq 3.46/3.47).
	return applyTrustUpdate(ctx, suspectNode, false, timestamp)
}

// GetDetection returns a single detection event by suspect node and
// timestamp.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetDetection(ctx contractapi.TransactionContextInterface, suspectNode string, timestamp int64) (*DetectionEvent, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%s:%d", keyPrefixDetection, suspectNode, timestamp)

	var event DetectionEvent
	if err := getState(ctx, key, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// GetAllDetections returns all logged detection events.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAllDetections(ctx contractapi.TransactionContextInterface) ([]*DetectionEvent, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixDetection)
	if err != nil {
		return nil, err
	}

	events := make([]*DetectionEvent, 0, len(results))
	for _, data := range results {
		var event DetectionEvent
		if err := unmarshalAsset(data, &event); err != nil {
			return nil, err
		}
		events = append(events, &event)
	}
	return events, nil
}
