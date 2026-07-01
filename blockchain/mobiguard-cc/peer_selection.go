package main

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)



// PeerSelectionResult is returned by QueryPeerSelection and contains
// the three node buckets: active peers, demoted clients, and removed
// nodes. The bridge (Phase 4) reads this to determine which RSU
// identities are eligible for endorsement at runtime.
type PeerSelectionResult struct {
	// ActivePeers: nodes with no current "demoted"/"removed" record.
	// Eligible for Fabric endorsement and PBFT consensus participation.
	
	ActivePeers []*NodeStatus `json:"activePeers"`

	// DemotedClients: nodes with a "demoted" quarantine record. Still in
	// the network and monitored, trust updates continue, but excluded from
	// peer selection. LiftQuarantine can reinstate them.
	DemotedClients []*NodeStatus `json:"demotedClients"`

	// RemovedNodes: nodes with a "removed" quarantine record. Permanently
	// ejected. No further writes accepted. Cannot be lifted.
	RemovedNodes []*NodeStatus `json:"removedNodes"`
}

// NodeStatus combines trust score and quarantine state for a node into
// one view, used inside PeerSelectionResult.
type NodeStatus struct {
	NodeId          string           `json:"nodeId"`
	TrustScore      int              `json:"trustScore"`      // basis points 0-10000
	QuarantineState QuarantineStatus `json:"quarantineState"` // "active_peer" | "demoted" | "removed"
	DemotedAt       int64            `json:"demotedAt"`       // 0 if never demoted
	RemovedAt       int64            `json:"removedAt"`       // 0 if not removed
}

// QuarantineStatusActivePeer is a virtual status used only in
// NodeStatus.QuarantineState to label nodes that have no quarantine
// record (full active peer). Does NOT appear in QuarantineRecord.Status.
const QuarantineStatusActivePeer QuarantineStatus = "active_peer"

// QueryPeerSelection returns the three-bucket peer classification for
// all nodes that have either a trust score or quarantine record on the
// ledger.
//
// Nodes that have never generated any ledger events (score implicitly
// 10000, no quarantine record) are NOT listed here -- they are
// implicitly active peers. The bridge should treat any node NOT in
// DemotedClients or RemovedNodes as eligible. 
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryPeerSelection(ctx contractapi.TransactionContextInterface) (*PeerSelectionResult, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	result := &PeerSelectionResult{
		ActivePeers:    make([]*NodeStatus, 0),
		DemotedClients: make([]*NodeStatus, 0),
		RemovedNodes:   make([]*NodeStatus, 0),
	}

	seenNodes := make(map[string]bool)

	// Pass 1: quarantine records define demoted/removed/lifted buckets.
	qResults, err := getStateByPrefix(ctx, keyPrefixQuarantine)
	if err != nil {
		return nil, err
	}

	for _, data := range qResults {
		var qRecord QuarantineRecord
		if err := unmarshalAsset(data, &qRecord); err != nil {
			return nil, err
		}

		
		score := initialTrustScore
		tKey := keyPrefixTrust + qRecord.NodeId
		tExists, err := assetExists(ctx, tKey)
		if err != nil {
			return nil, err
		}
		if tExists {
			var trust TrustScore
			if err := getState(ctx, tKey, &trust); err != nil {
				return nil, err
			}
			score = trust.Score
		}

		ns := &NodeStatus{
			NodeId:     qRecord.NodeId,
			TrustScore: score,
			DemotedAt:  qRecord.DemotedAt,
			RemovedAt:  qRecord.RemovedAt,
		}

		switch qRecord.Status {
		case QuarantineDemoted:
			ns.QuarantineState = QuarantineDemoted
			result.DemotedClients = append(result.DemotedClients, ns)
		case QuarantineRemoved:
			ns.QuarantineState = QuarantineRemoved
			result.RemovedNodes = append(result.RemovedNodes, ns)
		case QuarantineLifted:
			// Reinstated -- active peer again.
			ns.QuarantineState = QuarantineStatusActivePeer
			result.ActivePeers = append(result.ActivePeers, ns)
		}

		seenNodes[qRecord.NodeId] = true
	}

	// Pass 2: trust-scored nodes with no quarantine record are active peers
	// whose score has moved from default but not yet hit T_demote. Include
	// for score health visibility.
	tResults, err := getStateByPrefix(ctx, keyPrefixTrust)
	if err != nil {
		return nil, err
	}

	for _, data := range tResults {
		var trust TrustScore
		if err := unmarshalAsset(data, &trust); err != nil {
			return nil, err
		}
		if seenNodes[trust.NodeId] {
			continue
		}
		result.ActivePeers = append(result.ActivePeers, &NodeStatus{
			NodeId:          trust.NodeId,
			TrustScore:      trust.Score,
			QuarantineState: QuarantineStatusActivePeer,
		})
	}

	return result, nil
}

// IsActivePeer returns true if nodeId is currently eligible for peer
// selection -- i.e. not demoted or removed. Convenience query for the
// bridge to gate a single node's eligibility without fetching the full
// peer selection result.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) IsActivePeer(ctx contractapi.TransactionContextInterface, nodeId string) (bool, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return false, err
	}

	key := keyPrefixQuarantine + nodeId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return false, err
	}
	if !exists {
		// No quarantine record = initial active state.
		return true, nil
	}

	var record QuarantineRecord
	if err := getState(ctx, key, &record); err != nil {
		return false, err
	}

	// Only "lifted" (previously demoted, then reinstated) counts as active.
	// "demoted" and "removed" both exclude from peer selection.
	return record.Status == QuarantineLifted, nil
}
