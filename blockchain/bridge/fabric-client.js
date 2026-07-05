'use strict';
// fabric-client.js
// MobiGuard Bridge — Hyperledger Fabric Gateway connection
//
// Manages one gateway connection per RSU identity stored in the wallet.
// The wallet is populated from the Fabric CA (fabric-ca-client enroll)
// under the test-network organizations directory.
//
// Usage:
//   const fc = require('./fabric-client');
//   await fc.init();
//   const result = await fc.submit('rsu-200', 'LogFlowMod', rsuId, hash, ts);
//   const value  = await fc.evaluate('rsu-200', 'QueryTrust', nodeId);

const path   = require('path');
const fs     = require('fs');
const grpc   = require('@grpc/grpc-js');
const { connect, hash: sdkHash, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// Paths — adjust if test-network was started from a different directory
// ─────────────────────────────────────────────────────────────────────────────
const FABRIC_DIR  = path.join(__dirname, '..', 'fabric-samples', 'test-network');
const ORG1_DIR    = path.join(FABRIC_DIR, 'organizations', 'peerOrganizations',
                               'org1.example.com');
const PEER_ENDPOINT = 'localhost:7051';
const CHANNEL_NAME  = 'mychannel';
const CHAINCODE_NAME = 'mobiguard-cc';
const MSP_ID = 'Org1MSP';

// ─────────────────────────────────────────────────────────────────────────────
// Wallet: loaded from filesystem paths produced by fabric-ca-client enroll.
// wallet/<identity>/msp/signcerts/  → certificate
// wallet/<identity>/msp/keystore/   → private key
// ─────────────────────────────────────────────────────────────────────────────
const WALLET_DIR = path.join(__dirname, 'wallet');

// Cache of open gateway connections keyed by identity name.
const gateways = {};
// Cache of Contract objects keyed by identity name.
const contracts = {};

// ─────────────────────────────────────────────────────────────────────────────
// loadIdentity(name)
// Returns { certificate, privateKey } for an enrolled identity.
// Supports two layouts:
//   (a) wallet/<name>/msp/signcerts/*.pem  +  wallet/<name>/msp/keystore/*_sk
//   (b) test-network admin layout (for bootstrap / fallback)
// ─────────────────────────────────────────────────────────────────────────────
function loadIdentity(name) {
    const mspDir = path.join(WALLET_DIR, name, 'msp');

    // Layout (a): fabric-ca-client enroll output
    const signcertsDir = path.join(mspDir, 'signcerts');
    const keystoreDir  = path.join(mspDir, 'keystore');

    if (fs.existsSync(signcertsDir) && fs.existsSync(keystoreDir)) {
        const certFile = fs.readdirSync(signcertsDir).find(f => f.endsWith('.pem'));
        const keyFile  = fs.readdirSync(keystoreDir).find(f => f.endsWith('_sk') || f.endsWith('.pem'));
        if (certFile && keyFile) {
            return {
                certificate: fs.readFileSync(path.join(signcertsDir, certFile)).toString(),
                privateKey:  fs.readFileSync(path.join(keystoreDir,  keyFile)).toString(),
            };
        }
    }

    // Layout (b): test-network Org1 admin fallback
    const adminMspDir = path.join(ORG1_DIR, 'users', 'Admin@org1.example.com', 'msp');
    const certDir2    = path.join(adminMspDir, 'signcerts');
    const keyDir2     = path.join(adminMspDir, 'keystore');
    const certFile2   = fs.readdirSync(certDir2).find(f => f.endsWith('.pem'));
    const keyFile2    = fs.readdirSync(keyDir2).find(f => f.endsWith('_sk') || f.endsWith('.pem'));
    console.warn(`[BRIDGE] wallet/${name} not found — falling back to Org1 Admin identity`);
    return {
        certificate: fs.readFileSync(path.join(certDir2, certFile2)).toString(),
        privateKey:  fs.readFileSync(path.join(keyDir2,  keyFile2)).toString(),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// getContract(identityName)
// Returns a cached (or newly opened) fabric-gateway Contract for identityName.
// ─────────────────────────────────────────────────────────────────────────────
async function getContract(identityName) {
    if (contracts[identityName]) return contracts[identityName];

    // TLS root cert for Org1 peer
    const tlsCertPath = path.join(ORG1_DIR, 'peers', 'peer0.org1.example.com',
                                   'tls', 'ca.crt');
    const tlsCert = fs.readFileSync(tlsCertPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsCert);

    const grpcClient = new grpc.Client(PEER_ENDPOINT, tlsCredentials, {
        'grpc.ssl_target_name_override': 'peer0.org1.example.com',
    });

    const { certificate, privateKey } = loadIdentity(identityName);

    const privateKeyObj = crypto.createPrivateKey(privateKey);
    const signer = signers.newPrivateKeySigner(privateKeyObj);

    const gateway = connect({
        client: grpcClient,
        identity: { mspId: MSP_ID, credentials: Buffer.from(certificate) },
        signer,
        hash: sdkHash.sha256,
    });

    gateways[identityName] = gateway;
    const network  = gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);
    contracts[identityName] = contract;

    console.log(`[BRIDGE] Connected to Fabric as ${identityName}`);
    return contract;
}

// ─────────────────────────────────────────────────────────────────────────────
// submit(identityName, fnName, ...args)
// Submits a state-changing transaction (write).
// Returns the response payload as a UTF-8 string.
// ─────────────────────────────────────────────────────────────────────────────
async function submit(identityName, fnName, ...args) {
    const contract = await getContract(identityName);
    const result = await contract.submitTransaction(fnName, ...args.map(String));
    return result.length ? Buffer.from(result).toString('utf8') : '';
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluate(identityName, fnName, ...args)
// Evaluates a read-only query (no ledger write).
// ─────────────────────────────────────────────────────────────────────────────
async function evaluate(identityName, fnName, ...args) {
    const contract = await getContract(identityName);
    const result = await contract.evaluateTransaction(fnName, ...args.map(String));
    return result.length ? Buffer.from(result).toString('utf8') : '';
}

// ─────────────────────────────────────────────────────────────────────────────
// close()
// Gracefully close all open gateway connections.
// ─────────────────────────────────────────────────────────────────────────────
function close() {
    for (const [name, gw] of Object.entries(gateways)) {
        gw.close();
        console.log(`[BRIDGE] Closed gateway for ${name}`);
    }
}

module.exports = { submit, evaluate, close };
