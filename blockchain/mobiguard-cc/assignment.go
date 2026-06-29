package main

import (
	"fmt"
	"math"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// -----------------------------------------------------------------------
// RSU registration and controller assignment
// Implements §3.4.11: Eq 3.51 (assignment), 3.53 (failover)
// -----------------------------------------------------------------------

// RegisterRSU records a stationary RSU's fixed geographic position.
// RSUs are roadside infrastructure — they never move, so position is
// registered once and never updated. This position is used for
// distance-based controller assignment (Eq 3.51 / 3.53).
//
// The rsuId here is the logical ns-3 RSU identifier (e.g. "rsu-01"),
// distinct from the Fabric certificate identity (cid.GetID()) used
// for access control. Both are recorded for cross-referencing.
//
// RSU-only (write).
func (c *MobiguardContract) RegisterRSU(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	latStr string,
	lngStr string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	key := keyPrefixRSURecord + rsuId

	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("RSU %s is already registered", rsuId)
	}

	lat, lng, err := parseLatLng(latStr, lngStr)
	if err != nil {
		return err
	}

	record := RSURecord{
		DocType:      "rsu",
		RsuId:        rsuId,
		Latitude:     lat,
		Longitude:    lng,
		RegisteredAt: timestamp,
	}

	return putState(ctx, key, record)
}

// AssignController explicitly assigns an RSU to a specific controller,
// recording the assignment on-chain (Eq 3.51). Called during initial
// network setup or when the bridge manually assigns after computing
// the nearest trusted controller.
//
// The assigned controller must be in ControllerTrusted status with
// trust score >= T_ctrl_min — i.e. it must be in Ctrusted(t).
//
// RSU-only (write).
func (c *MobiguardContract) AssignController(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	controllerId string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	// Verify the target controller is currently trusted.
	if err := requireControllerTrusted(ctx, controllerId); err != nil {
		return err
	}

	return recordAssignment(ctx, rsuId, controllerId, timestamp)
}

// AutoAssignController automatically assigns an RSU to the nearest
// trusted controller in Ctrusted(t), implementing Eq 3.51:
//
//	c*(k,t) = arg min  d(rk, ci)
//	           ci ∈ Ctrusted(t)
//
// Requires both the RSU and all candidate controllers to be registered
// with geographic coordinates. Uses the Haversine formula for d(rk,ci).
//
// RSU-only (write).
func (c *MobiguardContract) AutoAssignController(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}

	// Get RSU position.
	rsuRecord, err := getRSURecord(ctx, rsuId)
	if err != nil {
		return fmt.Errorf(
			"RSU %s not found — register it first via RegisterRSU: %v",
			rsuId, err,
		)
	}

	// Get all trusted controllers.
	trustedControllers, err := getTrustedControllerRecords(ctx)
	if err != nil {
		return err
	}
	if len(trustedControllers) == 0 {
		return fmt.Errorf(
			"no trusted controllers available for assignment to RSU %s", rsuId,
		)
	}

	// Eq 3.51: find nearest trusted controller by Haversine distance.
	nearest, err := findNearestController(
		rsuRecord.Latitude, rsuRecord.Longitude, trustedControllers, "",
	)
	if err != nil {
		return err
	}

	return recordAssignment(ctx, rsuId, nearest.ControllerId, timestamp)
}

// FailoverRSU reassigns a single RSU to the nearest trusted controller
// excluding the revoked one, implementing Eq 3.53:
//
//	c*(k, t+) = arg min  d(rk, cj)
//	             cj ∈ Ctrusted(t)\{ci}
//
// Called automatically by TriggerFailoverAll when SC.Revoke fires,
// or can be called manually by the bridge.
//
// RSU-only (write).
func (c *MobiguardContract) FailoverRSU(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	revokedControllerId string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}
	return failoverSingleRSU(ctx, rsuId, revokedControllerId, timestamp)
}

// TriggerFailoverAll is called automatically by SubmitConflictEvidence
// when SC.Revoke fires. It finds all RSUs currently assigned to the
// revoked controller and reassigns each to the nearest remaining trusted
// controller (Eq 3.53).
//
// Also exposed as a public function so the bridge can trigger it
// explicitly if needed.
//
// RSU-only (write).
func (c *MobiguardContract) TriggerFailoverAll(
	ctx contractapi.TransactionContextInterface,
	revokedControllerId string,
	timestamp int64,
) error {
	if _, err := requireRSU(ctx); err != nil {
		return err
	}
	return triggerFailoverAll(ctx, revokedControllerId, timestamp)
}

// QueryControllerAssignment returns the current controller assignment
// for a specific RSU.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) QueryControllerAssignment(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
) (*RSUAssignment, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	key := keyPrefixAssignment + rsuId
	var assignment RSUAssignment
	if err := getState(ctx, key, &assignment); err != nil {
		return nil, err
	}
	return &assignment, nil
}

// GetAllAssignments returns the full RSU-to-controller assignment map.
// Useful for the bridge to get a complete network view.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetAllAssignments(
	ctx contractapi.TransactionContextInterface,
) ([]*RSUAssignment, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}

	results, err := getStateByPrefix(ctx, keyPrefixAssignment)
	if err != nil {
		return nil, err
	}

	assignments := make([]*RSUAssignment, 0)
	for _, data := range results {
		var a RSUAssignment
		if err := unmarshalAsset(data, &a); err != nil {
			return nil, err
		}
		assignments = append(assignments, &a)
	}
	return assignments, nil
}

// GetRSURecord returns the registration record for a specific RSU.
//
// Read-only (RSU or Controller).
func (c *MobiguardContract) GetRSURecord(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
) (*RSURecord, error) {
	if err := requireKnownOrg(ctx); err != nil {
		return nil, err
	}
	return getRSURecord(ctx, rsuId)
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

// triggerFailoverAll finds all RSUs assigned to revokedControllerId
// and reassigns each to the nearest remaining trusted controller.
// This is the automatic failover triggered by SC.Revoke (Eq 3.53).
func triggerFailoverAll(
	ctx contractapi.TransactionContextInterface,
	revokedControllerId string,
	timestamp int64,
) error {
	// Get all assignments.
	results, err := getStateByPrefix(ctx, keyPrefixAssignment)
	if err != nil {
		return err
	}

	for _, data := range results {
		var assignment RSUAssignment
		if err := unmarshalAsset(data, &assignment); err != nil {
			return err
		}
		// Only reassign RSUs currently assigned to the revoked controller.
		if assignment.ControllerId == revokedControllerId {
			if err := failoverSingleRSU(
				ctx,
				assignment.RsuId,
				revokedControllerId,
				timestamp,
			); err != nil {
				// Log error but continue reassigning other RSUs.
				// A single RSU failover failure should not block others.
				continue
			}
		}
	}
	return nil
}

// failoverSingleRSU implements Eq 3.53 for one RSU: finds nearest
// trusted controller excluding revokedControllerId and records the
// new assignment.
func failoverSingleRSU(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	revokedControllerId string,
	timestamp int64,
) error {
	rsuRecord, err := getRSURecord(ctx, rsuId)
	if err != nil {
		return fmt.Errorf(
			"failover failed for RSU %s: position not registered: %v",
			rsuId, err,
		)
	}

	trustedControllers, err := getTrustedControllerRecords(ctx)
	if err != nil {
		return err
	}

	// Eq 3.53: Ctrusted(t) \ {ci} — exclude the revoked controller.
	if len(trustedControllers) == 0 {
		return fmt.Errorf(
			"no trusted controllers available for failover of RSU %s", rsuId,
		)
	}

	nearest, err := findNearestController(
		rsuRecord.Latitude,
		rsuRecord.Longitude,
		trustedControllers,
		revokedControllerId, // excluded from selection
	)
	if err != nil {
		return fmt.Errorf(
			"failover failed for RSU %s: %v", rsuId, err,
		)
	}

	return recordAssignment(ctx, rsuId, nearest.ControllerId, timestamp)
}

// recordAssignment writes or updates an RSUAssignment record.
// Preserves the previous controller ID for audit trail and increments
// failover count on each reassignment.
func recordAssignment(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
	controllerId string,
	timestamp int64,
) error {
	key := keyPrefixAssignment + rsuId

	var existing RSUAssignment
	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}

	if exists {
		if err := getState(ctx, key, &existing); err != nil {
			return err
		}
	}

	previousController := ""
	failoverCount := 0
	if exists {
		previousController = existing.ControllerId
		failoverCount = existing.FailoverCount + 1
	}

	assignment := RSUAssignment{
		DocType:            "assignment",
		RsuId:              rsuId,
		ControllerId:       controllerId,
		AssignedAt:         timestamp,
		PreviousController: previousController,
		FailoverCount:      failoverCount,
	}

	return putState(ctx, key, assignment)
}

// getRSURecord reads the RSURecord for rsuId from the ledger.
func getRSURecord(
	ctx contractapi.TransactionContextInterface,
	rsuId string,
) (*RSURecord, error) {
	key := keyPrefixRSURecord + rsuId
	var record RSURecord
	if err := getState(ctx, key, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// getTrustedControllerRecords returns all ControllerRecord entries
// currently in Ctrusted(t) — status=trusted AND score >= T_ctrl_min.
func getTrustedControllerRecords(
	ctx contractapi.TransactionContextInterface,
) ([]*ControllerRecord, error) {
	results, err := getStateByPrefix(ctx, keyPrefixController)
	if err != nil {
		return nil, err
	}

	trusted := make([]*ControllerRecord, 0)
	for _, data := range results {
		var record ControllerRecord
		if err := unmarshalAsset(data, &record); err != nil {
			return nil, err
		}
		if record.Status == ControllerTrusted &&
			record.TrustScore >= defaultCtrlTrustMin {
			trusted = append(trusted, &record)
		}
	}
	return trusted, nil
}

// findNearestController implements arg min d(rk, ci) from Eq 3.51/3.53.
// excludeId is the revoked controller to skip (empty string = no exclusion).
// Returns an error if no eligible controller is found after exclusion.
func findNearestController(
	rsuLat, rsuLng float64,
	controllers []*ControllerRecord,
	excludeId string,
) (*ControllerRecord, error) {
	var nearest *ControllerRecord
	minDist := math.MaxFloat64

	for _, ctrl := range controllers {
		if ctrl.ControllerId == excludeId {
			continue // Eq 3.53: exclude revoked controller
		}
		dist := haversineDistance(rsuLat, rsuLng, ctrl.Latitude, ctrl.Longitude)
		if dist < minDist {
			minDist = dist
			nearest = ctrl
		}
	}

	if nearest == nil {
		return nil, fmt.Errorf(
			"no eligible trusted controller found (excluding %q)", excludeId,
		)
	}
	return nearest, nil
}

// haversineDistance computes the great-circle distance in meters between
// two geographic coordinates using the Haversine formula.
// This implements the distance metric d(rk, ci) from Eq 3.51/3.53.
//
//	a = sin²(Δlat/2) + cos(lat1)·cos(lat2)·sin²(Δlng/2)
//	c = 2·atan2(√a, √(1−a))
//	d = R·c   where R = 6,371,000 m (Earth radius)
func haversineDistance(lat1, lng1, lat2, lng2 float64) float64 {
	const earthRadiusM = 6_371_000.0

	dLat := degreesToRadians(lat2 - lat1)
	dLng := degreesToRadians(lng2 - lng1)

	lat1Rad := degreesToRadians(lat1)
	lat2Rad := degreesToRadians(lat2)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(dLng/2)*math.Sin(dLng/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusM * c
}

// degreesToRadians converts decimal degrees to radians.
func degreesToRadians(deg float64) float64 {
	return deg * math.Pi / 180.0
}

// requireControllerTrusted returns an error if the controller is not
// currently in the trusted set Ctrusted(t).
func requireControllerTrusted(
	ctx contractapi.TransactionContextInterface,
	controllerId string,
) error {
	key := keyPrefixController + controllerId
	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf(
			"controller %s is not registered", controllerId,
		)
	}

	var record ControllerRecord
	if err := getState(ctx, key, &record); err != nil {
		return err
	}

	if record.Status == ControllerRevoked {
		return fmt.Errorf(
			"controller %s has been revoked and cannot accept RSU assignments",
			controllerId,
		)
	}
	if record.TrustScore < defaultCtrlTrustMin {
		return fmt.Errorf(
			"controller %s trust score %d is below T_ctrl_min %d",
			controllerId, record.TrustScore, defaultCtrlTrustMin,
		)
	}
	return nil
}
