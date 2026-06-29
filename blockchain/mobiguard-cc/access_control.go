package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// requireRSU enforces that the calling client identity belongs to
// RSUOrgMSP (Org1MSP in the current test-network mapping). All write
// functions for the six asset types must call this first.
//
// On success, returns the caller's distinct client identity string
// (cid.GetID()), used as the rsuId / endorser identity in written assets.
//
// Per zero-trust architecture (§3.4.10, Table 3.3): all blockchain writes
// originate exclusively from RSUs. ControllerOrgMSP identities are
// rejected here even if the Fabric endorsement policy would allow the tx.
func requireRSU(ctx contractapi.TransactionContextInterface) (string, error) {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if mspID != rsuOrgMSP {
		return "", fmt.Errorf("access denied: write operations require %s identity, got %s", rsuOrgMSP, mspID)
	}

	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client identity ID: %v", err)
	}
	return id, nil
}

// requireKnownOrg enforces that the calling client identity belongs to
// either RSUOrgMSP or ControllerOrgMSP. All query (read-only) functions
// call this so that only registered network participants can read ledger
// state. Both RSUs and controllers have BC Read access per Table 3.3.
func requireKnownOrg(ctx contractapi.TransactionContextInterface) error {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if mspID != rsuOrgMSP && mspID != controllerOrgMSP {
		return fmt.Errorf("access denied: read operations require %s or %s identity, got %s", rsuOrgMSP, controllerOrgMSP, mspID)
	}
	return nil
}

// requireNotRemoved checks whether nodeId has a QuarantineRemoved record
// on the ledger and returns an error if so. Called at the top of any
// write function that targets a specific node (LogDetection, SubmitAlert)
// to enforce the supervisor rule: ejected nodes generate no further
// ledger state at all.
//
// Note: applyTrustUpdate also has its own inline removed-check, but
// LogDetection and SubmitAlert write their own asset records *before*
// calling applyTrustUpdate — so the check must happen here first to
// prevent a partial write (detection record created even though the
// subsequent trust update would fail).
func requireNotRemoved(ctx contractapi.TransactionContextInterface, nodeId string) error {
	key := keyPrefixQuarantine + nodeId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to check quarantine status for node %s: %v", nodeId, err)
	}
	if !exists {
		return nil // no quarantine record = active node, allow write
	}

	var record QuarantineRecord
	if err := getState(ctx, key, &record); err != nil {
		return err
	}
	if record.Status == QuarantineRemoved {
		return fmt.Errorf("node %s has been removed from the system; all writes are permanently blocked", nodeId)
	}
	return nil
}
