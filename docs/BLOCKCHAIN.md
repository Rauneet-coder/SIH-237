# Hyperledger Fabric Guide — SIH26237

> Everything an AI agent or developer needs to know about the blockchain layer in this project, from scratch.

---

## 1. What is Hyperledger Fabric?

Hyperledger Fabric is an **enterprise-grade, permissioned blockchain framework** developed by the Linux Foundation. Unlike public blockchains (Ethereum, Bitcoin), Fabric:

- Requires **identity verification** to join — no anonymous participants
- Has **no cryptocurrency** — no gas, no tokens, no mining
- Supports **private transactions** — data visible only to authorized parties
- Is **configurable** — consensus, endorsement policies, channel privacy
- Is designed for **enterprise/government** use cases

### Why Not Ethereum or Bitcoin?
| Concern | Public Blockchain | Hyperledger Fabric |
|---|---|---|
| Privacy | All data is public | Data stays within consortium |
| Cost | Gas fees per transaction | No transaction cost |
| Speed | 15–30 TPS | 3000+ TPS |
| Identity | Pseudonymous | Certificate-based (MSP) |
| Suitable for MoD | ❌ No | ✅ Yes |

---

## 2. Core Concepts

### 2.1 Peers
Peers are nodes that host the blockchain ledger and execute chaincode (smart contracts). In our network:
- `peer0.org1.example.com` — Primary peer
- `peer1.org1.example.com` — Secondary peer (redundancy)

### 2.2 Orderer
The orderer is responsible for consensus — it receives endorsed transactions, orders them, and packages them into blocks. We use **RAFT consensus** (crash fault tolerant, suitable for private networks).

### 2.3 Channel
A channel is a private subnet within the Fabric network. Transactions on a channel are only visible to peers that joined that channel. Our channel: `provchannel`.

### 2.4 Chaincode (Smart Contracts)
Chaincode is the application logic that runs on peers. It defines what state can be written to the ledger and how. Our chaincode: written in **Go**, deployed to `provchannel`.

### 2.5 MSP (Membership Service Provider)
MSP manages digital identities in the Fabric network. It uses X.509 certificates issued by a Certificate Authority (CA). Only entities with valid MSP certificates can submit transactions.

### 2.6 CouchDB
The state database (world state) for Fabric. We use CouchDB instead of the default LevelDB because CouchDB supports **rich JSON queries** — essential for querying by watermarkID, recipientID, etc.

### 2.7 Ledger
The ledger has two components:
- **World State (CouchDB):** Current state of all key-value pairs
- **Blockchain (files):** Immutable log of all transactions — you can replay history

---

## 3. Our Network Configuration

### Network Topology
```
Org1 (Ministry of Defence Internal)
├── CA: ca.org1.example.com:7054
├── Peer0: peer0.org1.example.com:7051
│   └── CouchDB: couchdb0:5984
├── Peer1: peer1.org1.example.com:8051
│   └── CouchDB: couchdb1:5984
└── Admin: Admin@org1.example.com

Orderer:
└── orderer.example.com:7050 (RAFT single-node for dev)

Channel: provchannel
Chaincode: provenance (installed on both peers)
```

### Channel Configuration (`configtx.yaml` summary)
```yaml
Profiles:
  ProvGenesis:           # For orderer genesis block
    Orderer:
      OrdererType: etcdraft
      Addresses: [orderer.example.com:7050]
    Consortiums:
      ProvConsortium:
        Organizations: [Org1]

  ProvChannel:           # For our application channel
    Consortium: ProvConsortium
    Application:
      Organizations: [Org1]
      Policies: (default Fabric policies)
```

---

## 4. Chaincode — The Smart Contract

File: `blockchain/chaincode/provenance/provenance.go`

### Data Structure
```go
// DecryptionEvent is the data stored on the ledger per decryption
type DecryptionEvent struct {
    EventID            string `json:"eventId"`
    DocHash            string `json:"docHash"`         // SHA3-256 of original doc
    DocCID             string `json:"docCID"`          // IPFS content ID
    RecipientID        string `json:"recipientId"`     // UUID of recipient user
    RecipientEmail     string `json:"recipientEmail"`  // For human-readable reports
    WatermarkID        string `json:"watermarkId"`     // SHA3-256(recipientId||CID||ts||nonce)
    Timestamp          int64  `json:"timestamp"`       // Unix timestamp
    DilithiumSignature string `json:"dilithiumSig"`    // Base64 Dilithium-3 signature
    DilithiumPublicKey string `json:"dilithiumPubKey"` // Base64 public key for verification
    SignatureVerified   bool   `json:"signatureVerified"` // Verified at log time
}
```

### Chaincode Functions

#### `LogDecryption` — Write a new event
```go
func (s *ProvenanceChaincode) LogDecryption(
    ctx contractapi.TransactionContextInterface,
    eventJSON string,
) error {
    var event DecryptionEvent
    json.Unmarshal([]byte(eventJSON), &event)

    // Validate required fields
    if event.EventID == "" || event.WatermarkID == "" {
        return fmt.Errorf("eventId and watermarkId are required")
    }

    // Check for duplicate (idempotent)
    existing, _ := ctx.GetStub().GetState(event.EventID)
    if existing != nil {
        return fmt.Errorf("event %s already exists", event.EventID)
    }

    // Write to ledger (immutable)
    data, _ := json.Marshal(event)
    return ctx.GetStub().PutState(event.EventID, data)
}
```

#### `QueryByWatermark` — Attribution query
```go
func (s *ProvenanceChaincode) QueryByWatermark(
    ctx contractapi.TransactionContextInterface,
    watermarkID string,
) ([]*DecryptionEvent, error) {
    // CouchDB rich query — works because we use CouchDB state DB
    query := fmt.Sprintf(
        `{"selector": {"watermarkId": "%s"}}`, watermarkID,
    )
    return executeRichQuery(ctx, query)
}
```

#### `QueryByRecipient` — All events for a recipient
```go
func (s *ProvenanceChaincode) QueryByRecipient(
    ctx contractapi.TransactionContextInterface,
    recipientID string,
) ([]*DecryptionEvent, error) {
    query := fmt.Sprintf(
        `{"selector": {"recipientId": "%s"}, "sort": [{"timestamp": "desc"}]}`,
        recipientID,
    )
    return executeRichQuery(ctx, query)
}
```

#### `QueryByDoc` — All decryptions of a document
```go
func (s *ProvenanceChaincode) QueryByDoc(
    ctx contractapi.TransactionContextInterface,
    docHash string,
) ([]*DecryptionEvent, error) {
    query := fmt.Sprintf(
        `{"selector": {"docHash": "%s"}}`, docHash,
    )
    return executeRichQuery(ctx, query)
}
```

> ⚠️ **There is NO UpdateEvent or DeleteEvent function.** The ledger is append-only by design. This is the security guarantee — even the system admin cannot erase a decryption record.

---

## 5. Interacting with Fabric from Python

We use the **Fabric Gateway** pattern — the Python backend connects to a Fabric peer via gRPC and submits/evaluates transactions.

```python
# backend/app/services/fabric_service.py
import grpc
from grpc import ssl_channel_credentials
from app.core.config import settings

async def log_decryption_event(event: dict) -> str:
    """Submit a LogDecryption transaction to Hyperledger Fabric."""
    import json

    # Connect to peer via gRPC + TLS
    credentials = ssl_channel_credentials(
        root_certificates=open(settings.FABRIC_TLS_CERT_PATH, "rb").read()
    )
    channel = grpc.secure_channel(
        f"{settings.FABRIC_GATEWAY_HOST}:{settings.FABRIC_GATEWAY_PORT}",
        credentials,
    )

    # Use Fabric Gateway SDK to submit transaction
    # (fabric-gateway-python library handles endorsement + ordering)
    from fabric_sdk_py.gateway import Gateway  # simplified example

    gateway = Gateway(channel, msp_id=settings.FABRIC_MSP_ID)
    network = gateway.get_network(settings.FABRIC_CHANNEL)
    contract = network.get_contract(settings.FABRIC_CHAINCODE)

    # Submit transaction (write to ledger)
    tx_id = await contract.submit_transaction(
        "LogDecryption", json.dumps(event)
    )
    return tx_id.decode()


async def query_by_watermark(watermark_id: str) -> list[dict]:
    """Query Fabric ledger for events matching a watermarkId."""
    # ... same connection setup ...
    result = await contract.evaluate_transaction(
        "QueryByWatermark", watermark_id
    )
    return json.loads(result)
```

---

## 6. Why the Ledger Cannot Be Tampered With

### The Immutability Guarantee
1. **Each block references the previous block's hash.** Changing any historical block invalidates all subsequent blocks.
2. **All peers maintain a copy.** Tampering requires compromising all peers simultaneously.
3. **The chaincode has no delete function.** Even if an attacker controls the application, they cannot call a delete that doesn't exist.
4. **MSP authentication.** Only entities with valid MSP certificates can submit transactions.

### Can an Admin Tamper?
- Application admin (FastAPI admin): No — they can only call API endpoints which call chaincode. Chaincode has no delete.
- Fabric admin: Theoretically could modify peer state files. This is mitigated by:
  - Running 2 peers (both must agree)
  - Orderer maintains the canonical chain
  - Blockchain hash chaining detects any modification

---

## 7. Querying the Ledger

### Via Python (evaluate — read-only, no transaction)
```python
# Query all decryption events for a document
events = await query_by_doc(doc_hash="sha3_256_value...")

# Query by watermark (for attribution)
events = await query_by_watermark(watermark_id="sha3_256_value...")
```

### Via Fabric CLI (for debugging)
```bash
# Enter the CLI container
docker exec -it fabric-cli bash

# Query the ledger
peer chaincode query \
  -C provchannel \
  -n provenance \
  -c '{"Args":["QueryByWatermark","sha3_256_watermark_id"]}'
```

---

## 8. Network Startup Sequence

```bash
# 1. Generate crypto material (certs, keys for all entities)
cd blockchain/scripts
./generate-crypto.sh

# 2. Create genesis block for orderer
configtxgen -profile ProvGenesis -channelID system-channel \
  -outputBlock ./network/channel-artifacts/genesis.block

# 3. Create channel transaction
configtxgen -profile ProvChannel -outputCreateChannelTx \
  ./network/channel-artifacts/provchannel.tx \
  -channelID provchannel

# 4. Start all containers
docker-compose up -d orderer peer0 peer1 couchdb0 couchdb1

# 5. Create channel and join peers
./create-channel.sh
./join-channel.sh

# 6. Deploy chaincode
./deploy-chaincode.sh

# 7. Verify
peer chaincode query -C provchannel -n provenance \
  -c '{"Args":["QueryByDoc","test"]}'
```
