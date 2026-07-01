package main

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// GetMyIdentity returns the calling client's cid.GetID() string and MSP
// ID. Useful for RSUs (and the Node.js bridge) to discover their own
// identity string for use as the rsuId in EndorseFlowMod,
// CommitModelHash, and VerifyModelHash — avoiding the need to parse or
// hardcode the full X.509 distinguished-name-based identity string.
//
// Read-only (RSU or Controller — either can check their own identity).
func (c *MobiguardContract) GetMyIdentity(ctx contractapi.TransactionContextInterface) (*IdentityInfo, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return nil, err
	}
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}

	return &IdentityInfo{ID: id, MSPID: mspID}, nil
}

// IdentityInfo is the return type for GetMyIdentity.
type IdentityInfo struct {
	ID    string `json:"id"`
	MSPID string `json:"mspId"`
}
