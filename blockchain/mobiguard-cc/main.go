package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	chaincode, err := contractapi.NewChaincode(&MobiguardContract{})
	if err != nil {
		log.Panicf("Error creating mobiguard-cc chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting mobiguard-cc chaincode: %v", err)
	}
}
