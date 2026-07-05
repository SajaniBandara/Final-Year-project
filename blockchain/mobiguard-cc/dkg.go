package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 7: DKG ceremony commits (eq:vk_commit, eq:vk_commit_rotated)
// -----------------------------------------------------------------------

// CommitDKG records a DKG ceremony or key-rotation result on the global
// anchor chain (eq:vk_commit / eq:vk_commit_rotated).
//
// Key: dkg:{round}
//
// round=1 is the initial ceremony; round>1 are triggered rotations
// (eq:key_rotation_trigger: ∃ r_j : T_{r_j} < T_min ∧ r_j ∈ P_DKG_current).
//
// vkZKP is the hex-encoded SHA3-512 of all per-RSU commitments:
//   vkZKP = H(Com_0 ‖ Com_1 ‖ … ‖ Com_{nRSUs-1})
//
// RSU-only write: only a participating RSU may commit the ceremony result.
func (c *MobiguardContract) CommitDKG(ctx contractapi.TransactionContextInterface,
	round int, vkZKP string, nRSUs int, commitments string, committedAt int64) error {

	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := fmt.Sprintf("%s%d", keyPrefixDKG, round)

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("DKG commit already exists for round %d", round)
	}

	commit := DKGCommit{
		DocType:     "dkg",
		Round:       round,
		VkZKP:       vkZKP,
		NRSUs:       nRSUs,
		Commitments: commitments,
		CommittedAt: committedAt,
	}

	return putState(ctx, key, commit)
}

// GetDKGCommit returns the DKG commit record for a given round.
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetDKGCommit(ctx contractapi.TransactionContextInterface, round int) (*DKGCommit, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%d", keyPrefixDKG, round)

	var commit DKGCommit
	if err := getState(ctx, key, &commit); err != nil {
		return nil, err
	}
	return &commit, nil
}
