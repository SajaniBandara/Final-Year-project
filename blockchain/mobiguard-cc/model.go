package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 5: Model hash commits (Eq 3.39)
// -----------------------------------------------------------------------

// CommitModelHash records a pre-commitment of an RSU's local federated
// LSTM model weight hash H(W_local^(k)) for a given training round
// (Eq 3.39, CommittedHash^(k)).
//
// Key: model:{rsuId}:{round}
//
// Created with Verified=false. VerifyModelHash is called afterward
// (e.g. during BRFA-v2 Step 2 / Algorithm 4) with the hash actually
// submitted for aggregation; if it matches, Verified is set to true.
//
// RSU-only (write). rsuId is taken from the caller's identity, so an
// RSU can only commit hashes for its own model.
func (c *MobiguardContract) CommitModelHash(ctx contractapi.TransactionContextInterface, round int, hash string, committedAt int64) error {
	rsuID, err := requireRSU(ctx)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s%s:%d", keyPrefixModel, rsuID, round)

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("model hash commit already exists for RSU %s round %d", rsuID, round)
	}

	commit := ModelHashCommit{
		DocType:     "model",
		RsuId:       rsuID,
		Round:       round,
		Hash:        hash,
		CommittedAt: committedAt,
		Verified:    false,
	}

	return putState(ctx, key, commit)
}

// VerifyModelHash implements the SC.VerifyModelHash check from Eq 3.39:
//
//	indicator^(k)_BC = SC.VerifyModelHash(H(W_local^(k)), CommittedHash^(k))
//
// Compares submittedHash against the previously committed hash for
// (rsuId, round). If they match, marks the record Verified=true and
// returns true. If they do not match, returns false WITHOUT mutating the
// record's Verified flag (so a failed verification attempt does not
// retroactively "un-verify" — it simply reports indicator^(k)_BC = 0 for
// this submission).
//
// RSU-only (write) — verification is part of the RSU-driven federated
// aggregation process (Algorithm 4, BRFA-v2), not a controller query,
// since the controller has no participation in aggregation validation
// (§3.4.9).
func (c *MobiguardContract) VerifyModelHash(ctx contractapi.TransactionContextInterface, rsuId string, round int, submittedHash string) (bool, error) {
	if _, err := requireRSU(ctx); err != nil {
		return false, err
	}

	key := fmt.Sprintf("%s%s:%d", keyPrefixModel, rsuId, round)

	var commit ModelHashCommit
	if err := getState(ctx, key, &commit); err != nil {
		return false, err
	}

	if commit.Hash != submittedHash {
		return false, nil
	}

	commit.Verified = true
	if err := putState(ctx, key, commit); err != nil {
		return false, err
	}

	return true, nil
}

// GetModelHash returns the model hash commit record for a given RSU and
// round.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetModelHash(ctx contractapi.TransactionContextInterface, rsuId string, round int) (*ModelHashCommit, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%s:%d", keyPrefixModel, rsuId, round)

	var commit ModelHashCommit
	if err := getState(ctx, key, &commit); err != nil {
		return nil, err
	}
	return &commit, nil
}
