package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ProvenanceRecord defines the authoritative immutable decryption provenance record on Hyperledger Fabric.
// Under NIST FIPS 203/204 & SIH-237 specifications, every decryption session commits a digitally
// signed, watermarked canonical record here prior to document release.
type ProvenanceRecord struct {
	EventID             string `json:"eventId"`
	EventDigest         string `json:"eventDigest"`
	DocumentID          string `json:"documentId"`
	DocumentHash        string `json:"documentHash"`
	RecipientID         string `json:"recipientId"`
	SessionID           string `json:"sessionId"`
	WatermarkID         string `json:"watermarkId"`
	WatermarkCommitment string `json:"watermarkCommitment"`
	SigningKeyID        string `json:"signingKeyId"`
	Signature           string `json:"signature"`
	Timestamp           string `json:"timestamp"`
	Status              string `json:"status"`
	ActorOrg            string `json:"actorOrg,omitempty"`
	TxID                string `json:"txId,omitempty"`
}

// DecryptionProvenanceContract implements the smart contract for recording and querying immutable provenance records
type DecryptionProvenanceContract struct {
	contractapi.Contract
}

// CreateEvent commits an immutable decryption provenance record to the ledger.
// Enforces that records cannot be overwritten, verifies required fields, and creates composite indices.
func (c *DecryptionProvenanceContract) CreateEvent(
	ctx contractapi.TransactionContextInterface,
	eventJSON string,
) (*ProvenanceRecord, error) {
	if eventJSON == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: eventJSON cannot be empty")
	}

	var record ProvenanceRecord
	err := json.Unmarshal([]byte(eventJSON), &record)
	if err != nil {
		return nil, fmt.Errorf("DESERIALIZATION_FAILED: invalid JSON format: %v", err)
	}

	// Validate mandatory cryptographic and forensic attribution fields
	if record.EventID == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: eventId is required")
	}
	if record.EventDigest == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: eventDigest is required")
	}
	if record.DocumentID == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: documentId is required")
	}
	if record.RecipientID == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: recipientId is required")
	}
	if record.WatermarkID == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: watermarkId is required")
	}
	if record.WatermarkCommitment == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: watermarkCommitment is required")
	}
	if record.Signature == "" {
		return nil, fmt.Errorf("VALIDATION_FAILED: signature is required")
	}

	// Invariant: Append-only ledger. Overwriting an existing record is strictly forbidden.
	existing, err := ctx.GetStub().GetState(record.EventID)
	if err != nil {
		return nil, fmt.Errorf("LEDGER_READ_FAILED: failed reading state for event %s: %v", record.EventID, err)
	}
	if existing != nil && len(existing) > 0 {
		return nil, fmt.Errorf("RECORD_ALREADY_EXISTS: Event ID %s is already committed. Fabric provenance records are immutable", record.EventID)
	}

	// Populate consensus and transaction metadata
	record.TxID = ctx.GetStub().GetTxID()
	record.Status = "COMMITTED"

	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err == nil && clientMSPID != "" {
		record.ActorOrg = clientMSPID
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("SERIALIZATION_FAILED: failed serializing provenance record: %v", err)
	}

	// 1. Put primary state record
	err = ctx.GetStub().PutState(record.EventID, recordBytes)
	if err != nil {
		return nil, fmt.Errorf("PUT_STATE_FAILED: failed storing event %s: %v", record.EventID, err)
	}

	// 2. Index by watermark commitment for forensic leak attribution
	watermarkKey, err := ctx.GetStub().CreateCompositeKey("watermark~event", []string{record.WatermarkCommitment, record.EventID})
	if err == nil {
		_ = ctx.GetStub().PutState(watermarkKey, []byte{0x00})
	}

	// 3. Index by watermark ID
	watermarkIdKey, err := ctx.GetStub().CreateCompositeKey("watermarkid~event", []string{record.WatermarkID, record.EventID})
	if err == nil {
		_ = ctx.GetStub().PutState(watermarkIdKey, []byte{0x00})
	}

	// 4. Index by document ID for audit history
	docKey, err := ctx.GetStub().CreateCompositeKey("doc~event", []string{record.DocumentID, record.EventID})
	if err == nil {
		_ = ctx.GetStub().PutState(docKey, []byte{0x00})
	}

	// 5. Index by recipient ID for user audit history
	recipientKey, err := ctx.GetStub().CreateCompositeKey("recipient~event", []string{record.RecipientID, record.EventID})
	if err == nil {
		_ = ctx.GetStub().PutState(recipientKey, []byte{0x00})
	}

	// 6. Index by session ID for decryption pipeline tracking
	if record.SessionID != "" {
		sessionKey, err := ctx.GetStub().CreateCompositeKey("session~event", []string{record.SessionID, record.EventID})
		if err == nil {
			_ = ctx.GetStub().PutState(sessionKey, []byte{0x00})
		}
	}

	// Emit Fabric blockchain event
	_ = ctx.GetStub().SetEvent("ProvenanceEventCommitted", recordBytes)

	return &record, nil
}

// GetEvent retrieves a provenance record by its unique event ID
func (c *DecryptionProvenanceContract) GetEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
) (*ProvenanceRecord, error) {
	if eventID == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: eventId cannot be empty")
	}

	recordBytes, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("LEDGER_READ_FAILED: failed reading event %s: %v", eventID, err)
	}
	if recordBytes == nil || len(recordBytes) == 0 {
		return nil, fmt.Errorf("EVENT_NOT_FOUND: provenance event %s not found on ledger", eventID)
	}

	var record ProvenanceRecord
	err = json.Unmarshal(recordBytes, &record)
	if err != nil {
		return nil, fmt.Errorf("DESERIALIZATION_FAILED: corrupted event data on ledger: %v", err)
	}

	return &record, nil
}

// QueryByWatermark locates provenance events matching either a watermark commitment or a watermark ID.
// This is the core lookup function used by the Forensic Leak Attribution Engine.
func (c *DecryptionProvenanceContract) QueryByWatermark(
	ctx contractapi.TransactionContextInterface,
	watermarkQuery string,
) ([]*ProvenanceRecord, error) {
	if watermarkQuery == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: watermarkQuery cannot be empty")
	}

	// Attempt CouchDB rich query first
	couchQuery := fmt.Sprintf(`{"selector":{"$or":[{"watermarkCommitment":"%s"},{"watermarkId":"%s"}]}}`, watermarkQuery, watermarkQuery)
	results, err := c.executeRichQuery(ctx, couchQuery)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	// Fallback to partial composite key search on watermark~event
	compositeResults, err := c.queryByCompositeKey(ctx, "watermark~event", watermarkQuery)
	if err == nil && len(compositeResults) > 0 {
		return compositeResults, nil
	}

	// Fallback to partial composite key search on watermarkid~event
	return c.queryByCompositeKey(ctx, "watermarkid~event", watermarkQuery)
}

// QueryByDocument returns all decryption provenance records associated with a specific document ID.
func (c *DecryptionProvenanceContract) QueryByDocument(
	ctx contractapi.TransactionContextInterface,
	documentID string,
) ([]*ProvenanceRecord, error) {
	if documentID == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: documentId cannot be empty")
	}

	// Attempt CouchDB query
	couchQuery := fmt.Sprintf(`{"selector":{"documentId":"%s"}}`, documentID)
	results, err := c.executeRichQuery(ctx, couchQuery)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	// Fallback to partial composite key
	return c.queryByCompositeKey(ctx, "doc~event", documentID)
}

// QueryByRecipient returns all decryption provenance records associated with a specific recipient.
func (c *DecryptionProvenanceContract) QueryByRecipient(
	ctx contractapi.TransactionContextInterface,
	recipientID string,
) ([]*ProvenanceRecord, error) {
	if recipientID == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: recipientId cannot be empty")
	}

	// Attempt CouchDB query
	couchQuery := fmt.Sprintf(`{"selector":{"recipientId":"%s"}}`, recipientID)
	results, err := c.executeRichQuery(ctx, couchQuery)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	// Fallback to partial composite key
	return c.queryByCompositeKey(ctx, "recipient~event", recipientID)
}

// VerifyEventIntegrity verifies that a recorded event on the ledger exists and contains all required cryptographic hashes.
func (c *DecryptionProvenanceContract) VerifyEventIntegrity(
	ctx contractapi.TransactionContextInterface,
	eventID string,
) (bool, error) {
	record, err := c.GetEvent(ctx, eventID)
	if err != nil {
		return false, err
	}

	if record.EventDigest == "" || record.Signature == "" || record.WatermarkCommitment == "" || record.DocumentHash == "" {
		return false, fmt.Errorf("CORRUPTED_RECORD: missing critical cryptographic fields in event %s", eventID)
	}

	return true, nil
}

// UpdateEvent is explicitly rejected to enforce the append-only invariant.
func (c *DecryptionProvenanceContract) UpdateEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	eventJSON string,
) error {
	return fmt.Errorf("IMMUTABLE_LEDGER: Update operations are strictly forbidden on the Hyperledger Fabric provenance ledger")
}

// DeleteEvent is explicitly rejected to enforce the append-only invariant.
func (c *DecryptionProvenanceContract) DeleteEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
) error {
	return fmt.Errorf("IMMUTABLE_LEDGER: Delete operations are strictly forbidden on the Hyperledger Fabric provenance ledger")
}

// Helper: executeRichQuery queries CouchDB state database
func (c *DecryptionProvenanceContract) executeRichQuery(
	ctx contractapi.TransactionContextInterface,
	query string,
) ([]*ProvenanceRecord, error) {
	iterator, err := ctx.GetStub().GetQueryResult(query)
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	var records []*ProvenanceRecord
	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		var record ProvenanceRecord
		if err := json.Unmarshal(response.Value, &record); err == nil {
			records = append(records, &record)
		}
	}
	return records, nil
}

// Helper: queryByCompositeKey iterates over partial composite key matches
func (c *DecryptionProvenanceContract) queryByCompositeKey(
	ctx contractapi.TransactionContextInterface,
	objectType string,
	prefixKey string,
) ([]*ProvenanceRecord, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(objectType, []string{prefixKey})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	var records []*ProvenanceRecord
	for iterator.HasNext() {
		responseRange, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(responseRange.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}

		eventID := compositeKeyParts[1]
		record, err := c.GetEvent(ctx, eventID)
		if err == nil && record != nil {
			records = append(records, record)
		}
	}

	return records, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&DecryptionProvenanceContract{})
	if err != nil {
		fmt.Printf("Error creating decryption provenance chaincode: %s\n", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting decryption provenance chaincode: %s\n", err.Error())
	}
}
