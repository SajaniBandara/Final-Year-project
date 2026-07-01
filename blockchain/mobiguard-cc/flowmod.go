package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// MobiguardContract implements the mobiguard-cc smart contract.
// (Receiver type shared across all six asset-type files in this package.)
type MobiguardContract struct {
	contractapi.Contract
}

// -----------------------------------------------------------------------
// Asset 1: FlowMod log / endorsement (Eq 3.41 / 3.43 / 3.44)
// -----------------------------------------------------------------------

// LogFlowMod records that an RSU has received a FlowMod from the
// controller, *before* installation (Eq 3.43, BC.LogFlowMod).
//
// Creates a "flowmod:{flowModHash}" record with status "pending" and no
// endorsements. If a record for this hash already exists, returns an
// error (a FlowMod should only be logged once, by the RSU that first
// received it; subsequent RSUs endorse via EndorseFlowMod).
//
// RSU-only (write).
func (c *MobiguardContract) LogFlowMod(ctx contractapi.TransactionContextInterface, flowModHash string, recvTimestamp int64) error {
	rsuID, err := requireRSU(ctx)
	if err != nil {
		return err
	}

	key := keyPrefixFlowMod + flowModHash

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("FlowMod record for hash %s already exists", flowModHash)
	}

	asset := FlowModAsset{
		DocType:       "flowmod",
		FlowModHash:   flowModHash,
		RsuId:         rsuID,
		RecvTimestamp: recvTimestamp,
		Endorsements:  []string{},
		Status:        FlowModPending,
	}

	return putState(ctx, key, asset)
}

// EndorseFlowMod appends the calling RSU's endorsement to an existing
// FlowMod record (Eq 3.40, epsilon_j signatures). Once the number of
// distinct endorsements reaches flowModEndorsementQuorum (f+1, Eq
// 3.41/3.48), the record's status flips to "committed" — this represents
// CP = BC.Commit(...).
//
// endorserSig is the BLS endorsement signature (Eq 3.40); it is stored
// implicitly via the caller's identity being appended to Endorsements.
// (The raw signature bytes are not persisted separately in this schema;
// only the endorsing RSU's identity is recorded. If signature payload
// storage is required later, extend FlowModAsset with a
// map[string]string of endorser -> signature.)
//
// RSU-only (write).
func (c *MobiguardContract) EndorseFlowMod(ctx contractapi.TransactionContextInterface, flowModHash string) error {
	rsuID, err := requireRSU(ctx)
	if err != nil {
		return err
	}

	key := keyPrefixFlowMod + flowModHash

	var asset FlowModAsset
	if err := getState(ctx, key, &asset); err != nil {
		return err
	}

	if asset.Status == FlowModUnauthorized {
		return fmt.Errorf("FlowMod %s has been marked unauthorized and cannot be endorsed", flowModHash)
	}

	for _, e := range asset.Endorsements {
		if e == rsuID {
			return fmt.Errorf("RSU %s has already endorsed FlowMod %s", rsuID, flowModHash)
		}
	}

	asset.Endorsements = append(asset.Endorsements, rsuID)

	if len(asset.Endorsements) >= flowModEndorsementQuorum {
		asset.Status = FlowModCommitted
	}

	return putState(ctx, key, asset)
}

// QueryUnauthorizedFlowMod implements funauth (Eq 3.44): a FlowMod hash
// is flagged unauthorized if no "committed" record exists for it — i.e.
// either no record was ever logged, or the record exists but has not
// reached the endorsement quorum.
//
// Returns true if the FlowMod is unauthorized (funauth = 1), false if a
// committed record exists (funauth = 0).
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryUnauthorizedFlowMod(ctx contractapi.TransactionContextInterface, flowModHash string) (bool, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return false, err
	}

	key := keyPrefixFlowMod + flowModHash

	exists, err := assetExists(ctx, key)
	if err != nil {
		return false, err
	}
	if !exists {
		// No BC.Query(CP) match at all -> funauth = 1.
		return true, nil
	}

	var asset FlowModAsset
	if err := getState(ctx, key, &asset); err != nil {
		return false, err
	}

	// funauth = 1 unless the record has reached committed status.
	return asset.Status != FlowModCommitted, nil
}

// GetFlowMod returns the full FlowMod record for a given hash.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetFlowMod(ctx contractapi.TransactionContextInterface, flowModHash string) (*FlowModAsset, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixFlowMod + flowModHash

	var asset FlowModAsset
	if err := getState(ctx, key, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}

// MarkFlowModUnauthorized allows an RSU to explicitly flag a FlowMod
// record as unauthorized (e.g. if an RSU independently determines via
// Eq 3.44 cross-checking that a received FlowMod has no valid
// commitment and will never reach quorum). This is provided as an
// explicit audit-trail action; QueryUnauthorizedFlowMod already returns
// true for any non-committed record regardless of this flag.
//
// RSU-only (write).
func (c *MobiguardContract) MarkFlowModUnauthorized(ctx contractapi.TransactionContextInterface, flowModHash string) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := keyPrefixFlowMod + flowModHash

	var asset FlowModAsset
	if err := getState(ctx, key, &asset); err != nil {
		return err
	}

	if asset.Status == FlowModCommitted {
		return fmt.Errorf("FlowMod %s is already committed and cannot be marked unauthorized", flowModHash)
	}

	asset.Status = FlowModUnauthorized
	return putState(ctx, key, asset)
}

// -----------------------------------------------------------------------
// Shared ledger helpers
// -----------------------------------------------------------------------

// assetExists returns true if a value exists for the given key.
func assetExists(ctx contractapi.TransactionContextInterface, key string) (bool, error) {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return data != nil, nil
}

// putState marshals v to JSON and writes it under key.
func putState(ctx contractapi.TransactionContextInterface, key string, v interface{}) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal asset for key %s: %v", key, err)
	}
	if err := ctx.GetStub().PutState(key, bytes); err != nil {
		return fmt.Errorf("failed to write to world state: %v", err)
	}
	return nil
}

// getState reads the value at key and unmarshals it into v. Returns an
// error if the key does not exist.
func getState(ctx contractapi.TransactionContextInterface, key string, v interface{}) error {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if data == nil {
		return fmt.Errorf("no asset found for key %s", key)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal asset for key %s: %v", key, err)
	}
	return nil
}
