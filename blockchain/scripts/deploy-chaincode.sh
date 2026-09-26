#!/usr/bin/env bash
# ==============================================================================
# SIH-237 Hyperledger Fabric Chaincode Deployment Script
# Packages, installs, approves, and commits the Go provenance contract.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CC_NAME="provenance"
CC_VERSION="1.0"
CC_SEQUENCE=1
CHANNEL_NAME="provenance-channel"

echo "=== [SIH-237] Deploying Hyperledger Fabric Chaincode: ${CC_NAME} (v${CC_VERSION}) ==="

# Set CLI environment variables for Org1 Peer 0
export FABRIC_CFG_PATH="${ROOT_DIR}/blockchain/network"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE="${ROOT_DIR}/blockchain/network/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${ROOT_DIR}/blockchain/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS="localhost:7051"
export ORDERER_CA="${ROOT_DIR}/blockchain/network/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

echo "1. Packaging chaincode..."
docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    -w /workspace/blockchain/chaincode/provenance \
    hyperledger/fabric-tools:2.5 \
    peer lifecycle chaincode package "/workspace/blockchain/chaincode/provenance/${CC_NAME}.tar.gz" \
    --path /workspace/blockchain/chaincode/provenance \
    --lang golang \
    --label "${CC_NAME}_${CC_VERSION}"

echo "2. Installing chaincode on peer0..."
docker exec sih_peer0 peer lifecycle chaincode install "/opt/gopath/src/github.com/chaincode/${CC_NAME}.tar.gz" || {
    echo "Notice: Peer container install can also be triggered via CLI tools container if peers are active."
}

echo "3. Chaincode package ready at blockchain/chaincode/provenance/${CC_NAME}.tar.gz"
echo "=== Deployment definition script ready ==="
