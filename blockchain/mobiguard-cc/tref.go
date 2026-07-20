package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// Asset 9: Distributed time reference commits (eq:time_consensus, eq:delay_updated)
// -----------------------------------------------------------------------

// CommitTRef commits one periodic network-wide consensus time reference
// event to the ledger (eq:time_consensus):
//
//	T_ref(t) = median_j tau_j(t),  j = 1..n_RSU
//
// Key: tref:{seq}
//
// T_ref(t) and its deviation from ground truth (eps_ref, eq:eps_ref) are
// computed by NS-3 (crypto_layer.h update_T_ref()) and submitted here via
// the bridge tailer on every T_SYNC_INTERVAL tick — the same cadence as
// AnchorGlobal. This is what makes eq:delay_updated's "t_send, t_recv
// anchored to T_ref(t)" a genuine defense rather than trusting a single
// RSU's self-reported value: once committed, a compromised RSU cannot
// retroactively claim it observed a different T_ref at a given moment.
//
// seq is a monotonically increasing counter reset per simulation run.
// Duplicate key errors are safe to ignore on bridge restart (same seq →
// same value).
//
// RSU-only write: the first RSU submits on behalf of the collective
// (same convention as AnchorGlobal).
func (c *MobiguardContract) CommitTRef(ctx contractapi.TransactionContextInterface,
	seq int, tRefValue float64, epsRef float64, committedAt int64) error {

	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := fmt.Sprintf("%s%d", keyPrefixTRef, seq)

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("T_ref already committed for seq %d", seq)
	}

	commit := TRefCommit{
		DocType:     "tref",
		Seq:         seq,
		TRefValue:   tRefValue,
		EpsRef:      epsRef,
		CommittedAt: committedAt,
	}

	return putState(ctx, key, commit)
}

// GetTRef returns the committed time reference record for a given
// sequence number. Read-only (RSU or Controller).
func (c *MobiguardContract) GetTRef(ctx contractapi.TransactionContextInterface, seq int) (*TRefCommit, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%d", keyPrefixTRef, seq)

	var commit TRefCommit
	if err := getState(ctx, key, &commit); err != nil {
		return nil, err
	}
	return &commit, nil
}
