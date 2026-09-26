package main

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// MockTransactionContext implements contractapi.TransactionContextInterface for unit tests
type MockTransactionContext struct {
	contractapi.TransactionContext
	stub *MockStub
}

func (m *MockTransactionContext) GetStub() shim.ChaincodeStubInterface {
	return m.stub
}

// MockStub implements minimal shim.ChaincodeStubInterface for in-memory testing
type MockStub struct {
	shim.ChaincodeStubInterface
	state       map[string][]byte
	events      map[string][]byte
	txID        string
	composite   map[string]bool
}

func NewMockStub() *MockStub {
	return &MockStub{
		state:     make(map[string][]byte),
		events:    make(map[string][]byte),
		txID:      "tx-mock-12345",
		composite: make(map[string]bool),
	}
}

func (m *MockStub) GetState(key string) ([]byte, error) {
	val, ok := m.state[key]
	if !ok {
		return nil, nil
	}
	return val, nil
}

func (m *MockStub) PutState(key string, value []byte) error {
	m.state[key] = value
	return nil
}

func (m *MockStub) GetTxID() string {
	return m.txID
}

func (m *MockStub) SetEvent(name string, payload []byte) error {
	m.events[name] = payload
	return nil
}

func (m *MockStub) CreateCompositeKey(objectType string, attributes []string) (string, error) {
	key := objectType
	for _, attr := range attributes {
		key += "\x00" + attr
	}
	m.composite[key] = true
	return key, nil
}

func TestDecryptionProvenanceContract_CreateEvent(t *testing.T) {
	contract := new(DecryptionProvenanceContract)
	stub := NewMockStub()
	ctx := &MockTransactionContext{stub: stub}

	validEvent := ProvenanceRecord{
		EventID:             "evt-test-001",
		EventDigest:         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		DocumentID:          "doc-test-100",
		DocumentHash:        "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		RecipientID:         "user-bob-99",
		SessionID:           "sess-9999",
		WatermarkID:         "wm-8888",
		WatermarkCommitment: "commit-7777",
		SigningKeyID:        "ML-DSA-65-V1",
		Signature:           "3045022100abcde...",
		Timestamp:           "2026-09-26T12:00:00Z",
	}

	eventBytes, err := json.Marshal(validEvent)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	// 1. Success case: Create new record
	created, err := contract.CreateEvent(ctx, string(eventBytes))
	if err != nil {
		t.Fatalf("CreateEvent failed: %v", err)
	}

	if created.EventID != validEvent.EventID {
		t.Errorf("Expected eventId %s, got %s", validEvent.EventID, created.EventID)
	}
	if created.TxID != stub.txID {
		t.Errorf("Expected txId %s, got %s", stub.txID, created.TxID)
	}
	if created.Status != "COMMITTED" {
		t.Errorf("Expected status COMMITTED, got %s", created.Status)
	}

	// 2. Immutability guarantee: Duplicate event creation must fail
	_, err = contract.CreateEvent(ctx, string(eventBytes))
	if err == nil {
		t.Fatalf("Expected error when attempting to overwrite existing record, but got nil")
	}

	// 3. Validation failure: Missing required field
	invalidEvent := validEvent
	invalidEvent.EventID = "evt-test-002"
	invalidEvent.WatermarkCommitment = "" // Missing watermark commitment
	invalidBytes, _ := json.Marshal(invalidEvent)

	_, err = contract.CreateEvent(ctx, string(invalidBytes))
	if err == nil {
		t.Fatalf("Expected validation error for missing watermarkCommitment, got nil")
	}
}

func TestDecryptionProvenanceContract_ImmutabilityRejection(t *testing.T) {
	contract := new(DecryptionProvenanceContract)
	stub := NewMockStub()
	ctx := &MockTransactionContext{stub: stub}

	// Verify UpdateEvent is rejected
	err := contract.UpdateEvent(ctx, "evt-001", "{}")
	if err == nil {
		t.Fatalf("Expected UpdateEvent to be rejected with immutable ledger error")
	}

	// Verify DeleteEvent is rejected
	err = contract.DeleteEvent(ctx, "evt-001")
	if err == nil {
		t.Fatalf("Expected DeleteEvent to be rejected with immutable ledger error")
	}
}

func TestDecryptionProvenanceContract_GetEvent(t *testing.T) {
	contract := new(DecryptionProvenanceContract)
	stub := NewMockStub()
	ctx := &MockTransactionContext{stub: stub}

	// Event not found
	_, err := contract.GetEvent(ctx, "non-existent-id")
	if err == nil {
		t.Fatalf("Expected error for non-existent event ID")
	}

	// Populate state
	record := ProvenanceRecord{
		EventID:             "evt-002",
		EventDigest:         "digest-002",
		DocumentID:          "doc-002",
		DocumentHash:        "dochash-002",
		RecipientID:         "rec-002",
		WatermarkID:         "wm-002",
		WatermarkCommitment: "commit-002",
		Signature:           "sig-002",
	}
	bytes, _ := json.Marshal(record)
	_ = stub.PutState(record.EventID, bytes)

	fetched, err := contract.GetEvent(ctx, "evt-002")
	if err != nil {
		t.Fatalf("Failed to get existing event: %v", err)
	}
	if fetched.EventDigest != "digest-002" {
		t.Errorf("Expected digest-002, got %s", fetched.EventDigest)
	}

	// Verify integrity
	valid, err := contract.VerifyEventIntegrity(ctx, "evt-002")
	if err != nil || !valid {
		t.Errorf("Expected integrity verification to pass, got err=%v, valid=%v", err, valid)
	}
}
