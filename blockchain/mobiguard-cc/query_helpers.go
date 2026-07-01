package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// getStateByPrefix returns the raw JSON bytes of all world-state entries
// whose key begins with prefix, using a half-open range query
// [prefix, prefix + '\uffff']. This relies on CouchDB's default
// lexicographic key ordering (test-network's peers run with CouchDB as
// state database, per PHASES.md Phase 1).
//
// NOTE: GetStateByRange returns an iterator that must be closed; this
// helper handles that internally and returns a plain slice, which is
// fine for the synthetic-data scale of Phase 2 testing. For production
// scale with thousands of entries per asset type, callers should switch
// to GetStateByRangeWithPagination.
func getStateByPrefix(ctx contractapi.TransactionContextInterface, prefix string) ([][]byte, error) {
	endKey := prefix + "\uffff"

	iterator, err := ctx.GetStub().GetStateByRange(prefix, endKey)
	if err != nil {
		return nil, fmt.Errorf("failed to range-query world state for prefix %s: %v", prefix, err)
	}
	defer iterator.Close()

	var results [][]byte
	for iterator.HasNext() {
		item, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate world state for prefix %s: %v", prefix, err)
		}
		results = append(results, item.Value)
	}
	return results, nil
}

// unmarshalAsset is a thin wrapper around json.Unmarshal with a
// consistent error message, used when iterating getStateByPrefix
// results.
func unmarshalAsset(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal asset: %v", err)
	}
	return nil
}
