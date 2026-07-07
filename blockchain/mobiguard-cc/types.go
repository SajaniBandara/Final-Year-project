package main

// =============================================================================
// mobiguard-cc — MOBIGUARD blockchain audit-trail chaincode
//
// Implements the six asset types from SPEC.md, mapped to the report's
// Security & Consensus Layer (§3.4.10) and signature equations (§3.4.4-3.4.9).
//
// Access control:
//   - RSUOrgMSP  : read + write (all six asset types)
//   - ControllerOrgMSP : read-only (queries only)
//   - Org-to-role mapping for the existing 2-peer test-network:
//       Org1 -> RSUOrgMSP
//       Org2 -> ControllerOrgMSP
//
// Byzantine fault tolerance parameter f:
//   - f = 1  =>  f+1 = 2   (FlowMod endorsement quorum, Eq 3.41/3.48)
//             =>  2f+1 = 3 (witness alert penalty quorum, Eq 3.24)
//   Defined as a package constant for now; can be migrated to a
//   chaincode-stored config asset once the real RSU count (from SUMO) is
//   known.
// =============================================================================

const (
	// MSP IDs for role-based access control.
	//
	// These map onto the existing Phase-1 test-network's default org
	// MSP IDs (Org1MSP / Org2MSP) by convention — see DEPLOY.md "Option
	// A". Org1 = RSUOrg (write access), Org2 = ControllerOrg
	// (read-only). 
	rsuOrgMSP        = "Org1MSP"
	controllerOrgMSP = "Org2MSP"

	byzantineF = 1
	// FlowMod endorsement quorum: f+1 distinct RSU endorsements required
	// before a FlowMod is considered "committed" (Eq 3.41 / 3.48).
	flowModEndorsementQuorum = byzantineF + 1
	// Witness alert penalty quorum: 2f+1 distinct verified witness alerts
	// required before SC.PenalizeTrust fires (Eq 3.24).
	witnessAlertQuorum = 2*byzantineF + 1

	// Trust score is stored as a scaled integer representing [0,1] in
	// basis points (0 - 10000) to avoid floating point non-determinism
	// across peers (Eq 3.46).
	trustScoreMax = 10000
	trustScoreMin = 0

	// Default trust reward/penalty increments (Δr / Δp, Eq 3.46),
	// expressed in basis points. 
	defaultTrustReward  = 100 // Δr = +0.01
	defaultTrustPenalty = 500 // Δp = -0.05

	//
	// Scale: 0 --- 1000 --- 3000 --- 10000
	//              removed  demoted  active(full peer)
	defaultTrustDemote = 3000 // T_demote = 0.30  (replaces old defaultTrustMin)
	defaultTrustRemove = 1000 // T_remove = 0.10

	// Initial trust score assigned to a previously-unseen node.
	// All nodes start as full peers; demotion only occurs after observed
	// misbehaviour drives the score below T_demote (Eq 3.46/3.47).
	// Per supervisor: "initially everyone as peers since trust scores
	// are just initialized."
	initialTrustScore = trustScoreMax // start fully trusted (1.0)
)

// -----------------------------------------------------------------------
// Asset 1: FlowMod log / endorsement (Eq 3.41 / 3.43 / 3.44)
// Key: flowmod:{hash}
// -----------------------------------------------------------------------

// FlowModStatus enumerates the lifecycle states of a FlowMod record.
type FlowModStatus string

const (
	FlowModPending      FlowModStatus = "pending"
	FlowModCommitted    FlowModStatus = "committed"
	FlowModUnauthorized FlowModStatus = "unauthorized"
)

// FlowModAsset represents a FlowMod log/endorsement record (Eq 3.41/3.43).
//
// LogFlowMod (Eq 3.43, BC.LogFlowMod) creates this record when an RSU
// receives a FlowMod from the controller, *before* installation, with
// status "pending" and zero endorsements.
//
// EndorseFlowMod (Eq 3.40/3.41) is called by neighboring RSUs to append
// their BLS endorsement signature; once len(Endorsements) >= f+1, status
// flips to "committed" (this represents CP = BC.Commit(...) in Eq 3.41).
//
// QueryUnauthorizedFlowMod (Eq 3.44, funauth) checks whether a FlowMod
// hash has a "committed" record; if not (absent, or stuck "pending"
// below quorum), it is flagged unauthorized.
type FlowModAsset struct {
	DocType       string        `json:"docType"` // constant "flowmod"
	FlowModHash   string        `json:"flowModHash"`
	RsuId         string        `json:"rsuId"` // RSU that first logged this FlowMod (Eq 3.43)
	RecvTimestamp int64         `json:"recvTimestamp"`
	Endorsements  []string      `json:"endorsements"` // RSU identity strings (Eq 3.40 signers)
	Status        FlowModStatus `json:"status"`
}

// -----------------------------------------------------------------------
// Asset 2: Detection events (Eq 3.42)
// Key: detect:{nodeId}:{ts}
// -----------------------------------------------------------------------

// DetectionEvent represents a logged detection event for signatures
// S1-S8 (Eq 3.42, BC.Write).
type DetectionEvent struct {
	DocType      string `json:"docType"` // constant "detection"
	SuspectNode  string `json:"suspectNode"`
	SignatureIdx int    `json:"signatureIndex"` // 1-8, corresponds to S1-S8
	Timestamp    int64  `json:"timestamp"`
	RsuId        string `json:"rsuId"` // writing RSU (Eq 3.42, r_k)
	RsuSig       string `json:"rsuSig"`
}

// -----------------------------------------------------------------------
// Asset 3: Trust scores (Eq 3.46)
// Key: trust:{nodeId}
// -----------------------------------------------------------------------

// TrustScore represents a node's blockchain-recorded trust score T_v
// (Eq 3.46), stored in basis points representing [0,1].
type TrustScore struct {
	DocType    string `json:"docType"` // constant "trust"
	NodeId     string `json:"nodeId"`
	Score      int    `json:"score"` // basis points, 0-10000 representing T_v in [0,1]
	LastUpdate int64  `json:"lastUpdate"`
}

// -----------------------------------------------------------------------
// Asset 4: Quarantine (Eq 3.47)
// Key: quarantine:{nodeId}
// -----------------------------------------------------------------------

// QuarantineStatus enumerates the three-state peer lifecycle per
// supervisor instruction:
//
//	active   -> score >= T_demote: full peer, participates in consensus
//	demoted  -> T_remove <= score < T_demote: peer->client demotion;
//	            still monitored, trust updates continue, can be lifted
//	removed  -> score < T_remove: ejected from system; all writes
//	            blocked, cannot be lifted (permanent)
type QuarantineStatus string

const (
	// QuarantineDemoted: RSU peer demoted to client state.
	// Triggered when trust score drops below defaultTrustDemote (0.30).
	// Maps to Eq 3.47 SC.Quarantine(v). Node is excluded from
	// QueryPeerSelection active-peer list but remains monitored.
	QuarantineDemoted QuarantineStatus = "demoted"

	// QuarantineRemoved: RSU ejected from the system entirely.
	// Triggered when trust score drops below defaultTrustRemove (0.10)
	// while already in QuarantineDemoted state. All subsequent writes
	// for this node (LogDetection, SubmitAlert, UpdateTrust) are
	// rejected. Cannot be lifted.
	QuarantineRemoved QuarantineStatus = "removed"

	// QuarantineLifted: demoted node manually reinstated to active peer.
	// Only valid transition from QuarantineDemoted; QuarantineRemoved
	// nodes cannot be lifted.
	QuarantineLifted QuarantineStatus = "lifted"
)

// QuarantineRecord records the demotion/removal lifecycle of an RSU node
// (Eq 3.47 + supervisor three-state model).
type QuarantineRecord struct {
	DocType    string           `json:"docType"` // constant "quarantine"
	NodeId     string           `json:"nodeId"`
	Status     QuarantineStatus `json:"status"`
	DemotedAt  int64            `json:"demotedAt"`  // timestamp of first demotion
	RemovedAt  int64            `json:"removedAt"`  // timestamp of removal (0 if not removed)
	LiftedAt   int64            `json:"liftedAt"`   // timestamp of last lift (0 if never lifted)
	Timestamp  int64            `json:"timestamp"`  // timestamp of most recent status change
}

// -----------------------------------------------------------------------
// Asset 5: Model hash commits (Eq 3.39)
// Key: model:{rsuId}:{round}
// -----------------------------------------------------------------------

// ModelHashCommit represents a federated LSTM model weight hash
// commitment (Eq 3.39, SC.VerifyModelHash / H(W_local)).
//
// CommitModelHash creates the record with Verified=false. VerifyModelHash
// is called separately (e.g. during BRFA-v2 Step 2, Algorithm 4) with the
// hash of the submitted weights; if it matches the committed hash,
// Verified is set true.
type ModelHashCommit struct {
	DocType     string `json:"docType"` // constant "model"
	RsuId       string `json:"rsuId"`
	Round       int    `json:"round"`
	Hash        string `json:"hash"`
	CommittedAt int64  `json:"committedAt"`
	Verified    bool   `json:"verified"`
}

// -----------------------------------------------------------------------
// Asset 6: Witness alerts (Eq 3.20-3.24)
// Key: alert:{packetHash}
// -----------------------------------------------------------------------

// AlertType enumerates the two witness alert types.
type AlertType string

const (
	AlertDuplication AlertType = "dup"     // alpha_w, Eq 3.20/3.22
	AlertNonForward  AlertType = "non-fwd" // beta_w, Eq 3.21/3.23
)

// WitnessAlert represents accumulated signed witness alerts for a given
// packet hash (Eq 3.20-3.24).
//
// NOTE: SuspectNode is an addition to SPEC.md's original schema
// ({type, alerts[], verifiedCount}), required so that SC.PenalizeTrust(v_i)
// (Eq 3.24) can identify which node to penalize once the 2f+1 quorum is
// reached. Agreed deviation — see chat history.
type WitnessAlert struct {
	DocType       string    `json:"docType"` // constant "alert"
	PacketHash    string    `json:"packetHash"`
	AlertType     AlertType `json:"type"`
	SuspectNode   string    `json:"suspectNode"` // v_i, the node to be penalized at quorum
	Alerts        []string  `json:"alerts"`      // witness identity strings with verified signed alerts
	VerifiedCount int       `json:"verifiedCount"`
	Penalized     bool      `json:"penalized"` // true once SC.PenalizeTrust has fired for this alert
}

// -----------------------------------------------------------------------
// Key prefixes (composite-key-free, simple string prefixes per SPEC.md)
// -----------------------------------------------------------------------

const (
	keyPrefixFlowMod    = "flowmod:"
	keyPrefixDetection  = "detect:"
	keyPrefixTrust      = "trust:"
	keyPrefixQuarantine = "quarantine:"
	keyPrefixModel      = "model:"
	keyPrefixAlert      = "alert:"
	keyPrefixDKG        = "dkg:"
	keyPrefixAnchor     = "anchor:"
	keyPrefixTRef       = "tref:"
)

// -----------------------------------------------------------------------
// Asset 8: Global anchor commits (eq:anchor_hash)
// Key: anchor:{seq}
// -----------------------------------------------------------------------

// GlobalAnchor records one periodic RSU-chain → global-chain anchor event.
// anchorHash = H(H_root^RSU ‖ ts_anchor ‖ H_prev^global) per eq:anchor_hash.
type GlobalAnchor struct {
	DocType      string `json:"docType"`      // constant "anchor"
	Seq          int    `json:"seq"`          // monotonically increasing per simulation
	AnchorHash   string `json:"anchorHash"`   // hex of H_anchor^(r)
	RsuChainLen  int    `json:"rsuChainLen"`  // RSU-chain length at anchor time
	CommittedAt  int64  `json:"committedAt"`  // ms since epoch
}

// -----------------------------------------------------------------------
// Asset 9: Distributed time reference commits (eq:time_consensus, eq:delay_updated)
// Key: tref:{seq}
// -----------------------------------------------------------------------

// TRefCommit records one periodic network-wide consensus time reference
// (T_ref(t) = median of RSU clocks, eq:time_consensus) on-chain, providing
// the tamper-evident audit trail main.tex (sec:time_ref) specifies:
// "T_ref(t) is committed to the blockchain by RSU consensus at regular
// intervals to provide a tamper-evident audit trail for all detection
// decisions." Detection code anchors t_send/t_recv to the most recently
// committed TRefValue (eq:delay_updated) rather than trusting any single
// RSU's self-reported local clock.
type TRefCommit struct {
	DocType     string  `json:"docType"`     // constant "tref"
	Seq         int     `json:"seq"`         // monotonically increasing per simulation
	TRefValue   float64 `json:"tRefValue"`   // T_ref(t), seconds since sim start
	EpsRef      float64 `json:"epsRef"`      // |T_ref(t) - T_ground(t)| at commit time (eq:eps_ref, M9)
	CommittedAt int64   `json:"committedAt"` // ms since epoch
}

// -----------------------------------------------------------------------
// Asset 7: DKG ceremony commits (eq:vk_commit, eq:vk_commit_rotated)
// Key: dkg:{round}  (round=1 initial ceremony; round>1 key rotations)
// -----------------------------------------------------------------------

// DKGCommit records a DKG ceremony or key-rotation result on the global
// anchor chain. vkZKP = SHA3-512(Com_0 ‖ … ‖ Com_{nRSUs-1}) per eq:vk_commit.
type DKGCommit struct {
	DocType     string `json:"docType"`     // constant "dkg"
	Round       int    `json:"round"`
	VkZKP       string `json:"vkZKP"`       // hex of H(Com_0 ‖ … ‖ Com_{nRSUs-1})
	NRSUs       int    `json:"nRSUs"`
	Commitments string `json:"commitments"` // hex of Com_0 ‖ … ‖ Com_{nRSUs-1} per eq:vk_commit
	CommittedAt int64  `json:"committedAt"` // ms since epoch
}

// -----------------------------------------------------------------------
// Controller trust constants (§3.4.11, Eq 3.49-3.53)
// -----------------------------------------------------------------------

const (
	// Controller trust thresholds — same scale as node trust (basis points).
	// T_ctrl_min = 0.30: below this SC.Revoke fires (Eq 3.52).
	defaultCtrlTrustMin     = 3000 // T_ctrl_min = 0.30
	defaultCtrlTrustReward  = 100  // same as node reward
	defaultCtrlTrustPenalty = 500  // same as node penalty
	initialCtrlTrustScore   = trustScoreMax // controllers start fully trusted

	// conflictEvidenceQuorum: number of distinct RSU conflict reports
	// required before a controller trust penalty is applied (Eq 3.50).
	// f+1 = 2 with byzantineF=1.
	conflictEvidenceQuorum = byzantineF + 1

	// Key prefixes for new asset types.
	keyPrefixController  = "controller:"
	keyPrefixAssignment  = "assignment:"
	keyPrefixConflict    = "conflict:"
	keyPrefixRSURecord   = "rsu:"
)

// -----------------------------------------------------------------------
// Controller status values (§3.4.11)
// -----------------------------------------------------------------------

type ControllerStatus string

const (
	// ControllerTrusted: controller is in Ctrusted(t), eligible for
	// RSU assignment (Eq 3.49).
	ControllerTrusted ControllerStatus = "trusted"

	// ControllerRevoked: SC.Revoke has fired (Eq 3.52). No RSU will
	// be assigned to this controller. Trust score still monitored.
	ControllerRevoked ControllerStatus = "revoked"
)

// -----------------------------------------------------------------------
// Asset: Controller registry (Eq 3.49 / 3.50 / 3.52)
// Key: controller:{controllerId}
// -----------------------------------------------------------------------

// ControllerRecord stores a registered SDVN controller's trust score,
// geographic position, and lifecycle status.
//
// Ctrusted(t) = {ci : TrustScore >= defaultCtrlTrustMin AND
//                     Status == ControllerTrusted} (Eq 3.49).
type ControllerRecord struct {
	DocType      string           `json:"docType"`      // "controller"
	ControllerId string           `json:"controllerId"` // c_i identifier
	Status       ControllerStatus `json:"status"`       // "trusted" | "revoked"
	TrustScore   int              `json:"trustScore"`   // basis points 0-10000
	Latitude     float64          `json:"latitude"`     // geographic position
	Longitude    float64          `json:"longitude"`    // for d(rk, ci) Eq 3.51
	RegisteredAt int64            `json:"registeredAt"`
	RevokedAt    int64            `json:"revokedAt"`  // 0 if not revoked
	LastUpdate   int64            `json:"lastUpdate"`
}

// -----------------------------------------------------------------------
// Asset: RSU registration (stationary position record)
// Key: rsu:{rsuId}
// -----------------------------------------------------------------------

// RSURecord stores the fixed geographic position of a registered RSU.
// RSUs are stationary infrastructure — position registered once, never
// updated. Used for distance-based controller assignment (Eq 3.51/3.53).
type RSURecord struct {
	DocType      string  `json:"docType"`      // "rsu"
	RsuId        string  `json:"rsuId"`        // r_k identifier
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	RegisteredAt int64   `json:"registeredAt"`
}

// -----------------------------------------------------------------------
// Asset: RSU-to-controller assignment (Eq 3.51 / 3.53)
// Key: assignment:{rsuId}
// -----------------------------------------------------------------------

// RSUAssignment records which controller an RSU is currently assigned
// to — c*(k,t) from Eq 3.51. Updated on initial assignment and on
// every failover (Eq 3.53).
type RSUAssignment struct {
	DocType            string `json:"docType"`            // "assignment"
	RsuId              string `json:"rsuId"`
	ControllerId       string `json:"controllerId"`       // current c*(k,t)
	AssignedAt         int64  `json:"assignedAt"`
	PreviousController string `json:"previousController"` // audit trail
	FailoverCount      int    `json:"failoverCount"`      // times reassigned
}

// -----------------------------------------------------------------------
// Asset: Conflict evidence (Eq 3.50)
// Key: conflict:{controllerId}:{rsuId}
// -----------------------------------------------------------------------

// ConflictEvidence records that an RSU detected an unauthorized FlowMod
// from a specific controller (funauth=1, Eq 3.44). When the count of
// distinct RSU reports for a controller reaches conflictEvidenceQuorum
// (f+1), the controller's trust score is penalized (Eq 3.50).
//
// One record per (controllerId, rsuId) pair — a single RSU cannot
// submit multiple conflict reports for the same controller to prevent
// a single compromised RSU from framing a legitimate controller.
type ConflictEvidence struct {
	DocType        string `json:"docType"`        // "conflict"
	ControllerId   string `json:"controllerId"`
	ReportingRsuId string `json:"reportingRsuId"`
	FlowModHash    string `json:"flowModHash"`    // which FlowMod triggered this
	Timestamp      int64  `json:"timestamp"`
}