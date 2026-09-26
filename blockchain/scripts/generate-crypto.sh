#!/usr/bin/env bash
# ==============================================================================
# SIH-237 Hyperledger Fabric Artifact Generator
# Generates cryptographic materials and channel configuration blocks
# Supports native fabric binaries or containerized fabric-tools execution.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NETWORK_DIR="${BLOCKCHAIN_DIR}/network"
CRYPTO_DIR="${NETWORK_DIR}/crypto-config"
ARTIFACTS_DIR="${NETWORK_DIR}/channel-artifacts"

echo "=== [SIH-237] Generating Fabric Cryptographic Artifacts ==="

mkdir -p "${ARTIFACTS_DIR}"
mkdir -p "${CRYPTO_DIR}"

# Determine whether to use local binaries or Docker hyperledger/fabric-tools
USE_DOCKER=false
if ! command -v cryptogen &> /dev/null || ! command -v configtxgen &> /dev/null; then
    echo "Notice: Native Fabric CLI tools (cryptogen/configtxgen) not found in PATH."
    echo "Falling back to official hyperledger/fabric-tools:2.5 container."
    USE_DOCKER=true
fi

if [ "$USE_DOCKER" = true ]; then
    # 1. Run cryptogen inside fabric-tools container
    echo "Generating crypto material via fabric-tools..."
    docker run --rm \
        -v "${NETWORK_DIR}:/network" \
        -w /network \
        hyperledger/fabric-tools:2.5 \
        cryptogen generate --config=crypto-config.yaml --output=crypto-config

    # 2. Run configtxgen inside fabric-tools container
    echo "Generating genesis block for orderer..."
    docker run --rm \
        -v "${NETWORK_DIR}:/network" \
        -w /network \
        -e FABRIC_CFG_PATH=/network/configtx \
        hyperledger/fabric-tools:2.5 \
        configtxgen -profile ProvGenesis -channelID sys-channel -outputBlock channel-artifacts/genesis.block

    echo "Generating channel creation transaction for ProvChannel..."
    docker run --rm \
        -v "${NETWORK_DIR}:/network" \
        -w /network \
        -e FABRIC_CFG_PATH=/network/configtx \
        hyperledger/fabric-tools:2.5 \
        configtxgen -profile ProvChannel -channelID provenance-channel -outputCreateChannelTx channel-artifacts/channel.tx

    echo "Generating anchor peer update transaction for Org1..."
    docker run --rm \
        -v "${NETWORK_DIR}:/network" \
        -w /network \
        -e FABRIC_CFG_PATH=/network/configtx \
        hyperledger/fabric-tools:2.5 \
        configtxgen -profile ProvChannel -channelID provenance-channel -outputAnchorPeersUpdate channel-artifacts/Org1MSPanchors.tx -asOrg Org1MSP
else
    # Native execution
    cd "${NETWORK_DIR}"
    cryptogen generate --config=crypto-config.yaml --output=crypto-config
    export FABRIC_CFG_PATH="${NETWORK_DIR}/configtx"
    configtxgen -profile ProvGenesis -channelID sys-channel -outputBlock channel-artifacts/genesis.block
    configtxgen -profile ProvChannel -channelID provenance-channel -outputCreateChannelTx channel-artifacts/channel.tx
    configtxgen -profile ProvChannel -channelID provenance-channel -outputAnchorPeersUpdate channel-artifacts/Org1MSPanchors.tx -asOrg Org1MSP
fi

echo "=== [SIH-237] Crypto and Channel Artifacts successfully generated in ${NETWORK_DIR} ==="
