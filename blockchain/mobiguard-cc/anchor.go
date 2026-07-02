package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 8: Global anchor commits (eq:anchor_hash)
// -----------------------------------------------------------------------

// AnchorGlobal commits one periodic RSU-chain → global-chain anchor event
// to the ledger (eq:anchor_hash):
//
//	H_anchor^(r) = H(H_root^RSU ‖ ts_anchor ‖ H_prev^global)
//
// Key: anchor:{seq}
//
// The anchor hash is computed by NS-3 (blockchain_sim.h bc_anchor_to_global)
// and submitted here via the bridge tailer. seq is a monotonically
// increasing counter reset per simulation run. Duplicate key errors are
// safe to ignore on bridge restart (same seq → same hash).
//
// RSU-only write: the first RSU submits on behalf of the collective.
func (c *MobiguardContract) AnchorGlobal(ctx contractapi.TransactionContextInterface,
	seq int, anchorHash string, rsuChainLen int, committedAt int64) error {

	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := fmt.Sprintf("%s%d", keyPrefixAnchor, seq)

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("anchor already committed for seq %d", seq)
	}

	anchor := GlobalAnchor{
		DocType:     "anchor",
		Seq:         seq,
		AnchorHash:  anchorHash,
		RsuChainLen: rsuChainLen,
		CommittedAt: committedAt,
	}

	return putState(ctx, key, anchor)
}

// GetAnchor returns the global anchor record for a given sequence number.
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAnchor(ctx contractapi.TransactionContextInterface, seq int) (*GlobalAnchor, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%d", keyPrefixAnchor, seq)

	var anchor GlobalAnchor
	if err := getState(ctx, key, &anchor); err != nil {
		return nil, err
	}
	return &anchor, nil
}
