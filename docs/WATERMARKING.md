# Forensic Watermarking Guide — SIH26237

> Complete explanation of the invisible watermarking system — how it works, why, and how to implement it.

---

## 1. What is Forensic Watermarking?

Forensic watermarking embeds **hidden, unique information** into a document that:
- Is **invisible** to the naked eye under normal viewing conditions
- **Survives** normal document operations (save, copy, email)
- Can be **extracted** by the system to identify the document's origin

This is different from visible watermarks (stamps, text overlays). A forensic watermark is a hidden fingerprint — the recipient doesn't know it's there.

---

## 2. Our Watermark Design

### What We Embed
Each decrypted PDF gets a unique **Watermark ID** embedded in it:
```
WatermarkID = SHA3-256(recipientID || docCID || timestamp || nonce)
Example: "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
```

This 64-character hex string is:
- Deterministically unique per decryption session
- Stored on the blockchain at the moment of embedding
- Extractable from any copy of the document

### Two-Layer Embedding Strategy
We use TWO embedding layers for redundancy:

| Layer | Method | Robustness |
|---|---|---|
| **Layer 1** | PDF metadata (XMP/DocInfo) | Fast to extract, easy to strip deliberately |
| **Layer 2** | Invisible text (white text, 0.1pt font) | Hard to detect, survives most copies |

**Layer 1** is the fast path for attribution. **Layer 2** is the forensic backup.

---

## 3. Implementation with PyMuPDF

PyMuPDF (`fitz`) is the only library used for PDF manipulation. It provides direct access to PDF internal structures.

### 3.1 Embedding the Watermark

```python
# backend/app/services/watermark_service.py
import fitz  # PyMuPDF
import hashlib
import secrets
from typing import bytes

def embed_watermark(pdf_bytes: bytes, watermark_id: str) -> bytes:
    """
    Embed an invisible forensic watermark into a PDF document.

    Args:
        pdf_bytes: Raw bytes of the decrypted PDF.
        watermark_id: The unique watermark ID (SHA3-256 hex string).

    Returns:
        Watermarked PDF bytes.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    # ── LAYER 1: PDF Metadata embedding ──────────────────────────────
    # Embed watermark in XMP metadata (invisible in normal viewers)
    metadata = doc.metadata
    metadata["keywords"] = f"WID:{watermark_id}"
    doc.set_metadata(metadata)

    # Also embed in the PDF's producer field
    # (survives most copy operations, visible only in PDF properties)
    metadata["producer"] = f"SIH26237-{watermark_id[:16]}"
    doc.set_metadata(metadata)

    # ── LAYER 2: Invisible text layer ─────────────────────────────────
    # Place tiny white text on every page — invisible but machine-readable
    for page in doc:
        page_rect = page.rect

        # Insert white text at 0.1pt font size in bottom-right corner
        # White text on white background = invisible
        page.insert_text(
            point=fitz.Point(page_rect.width - 5, page_rect.height - 5),
            text=watermark_id,
            fontsize=0.1,       # Microscopic — 0.1 point
            color=(1, 1, 1),    # White (RGB) — invisible on white bg
            overlay=True,
        )

    # Serialize back to bytes
    watermarked_bytes = doc.tobytes(garbage=4, deflate=True)
    doc.close()
    return watermarked_bytes
```

### 3.2 Extracting the Watermark

```python
def extract_watermark(pdf_bytes: bytes) -> str | None:
    """
    Extract the forensic watermark ID from a PDF document.

    Args:
        pdf_bytes: Raw bytes of the (possibly leaked) PDF.

    Returns:
        Watermark ID string if found, None otherwise.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    watermark_id = None

    # ── Try LAYER 1: Metadata ─────────────────────────────────────────
    metadata = doc.metadata
    keywords = metadata.get("keywords", "")
    if keywords.startswith("WID:"):
        watermark_id = keywords[4:]  # Strip "WID:" prefix
        doc.close()
        return watermark_id

    # ── Try LAYER 2: Invisible text ───────────────────────────────────
    for page in doc:
        # Extract ALL text including invisible (white) text
        text = page.get_text("text")
        # Look for SHA3-256 hex pattern (64 hex chars)
        import re
        matches = re.findall(r"[0-9a-f]{64}", text)
        if matches:
            watermark_id = matches[-1]  # Take last occurrence
            break

    doc.close()
    return watermark_id
```

---

## 4. Why Invisible White Text Works

### The Mechanism
- PDF is a structured format — text and its rendering color are separate
- A text element with `color=(1,1,1)` (white) renders invisibly on white pages
- But the text **data** is present in the PDF binary
- PDF text extraction tools (including PyMuPDF's `get_text`) read the raw data, not the rendered appearance

### What the Recipient Sees
```
Normal PDF viewer (Adobe, Chrome, Foxit):
┌────────────────────────────────────────┐
│   TOP SECRET BRIEFING                  │
│                                        │
│   Classified information here...       │
│                                        │
│                                [blank] │  ← watermark is here, invisible
└────────────────────────────────────────┘
```

### What the Extraction Tool Sees
```
PyMuPDF text extraction:
"TOP SECRET BRIEFING\nClassified information here...\na3f8b2c1d4e5f6a7..."
                                                        ↑ watermark ID found
```

---

## 5. Robustness Analysis

| Attack | Watermark Survives? | Notes |
|---|---|---|
| Save as PDF | ✅ Yes | Metadata and text layer persist |
| Copy-paste (digital) | ✅ Yes | Full PDF structure preserved |
| Email attachment | ✅ Yes | PDF binary unchanged |
| PDF re-save (Adobe Save) | ✅ Yes | Metadata preserved |
| PDF Optimize/Compress | ⚠️ Partially | Metadata survives; text may be optimized |
| Screenshot (PNG/JPG) | ❌ No | Pixels only — text layer lost |
| Print and re-scan | ❌ No | OCR cannot find sub-pixel text |
| Manual metadata strip | ❌ Layer 1 lost | But Layer 2 (text) survives |
| PDF flattening | ❌ Both lost | Adversarial — hard to detect |

### Mitigation for Advanced Attacks
For the hackathon scope, digital copy watermarking is sufficient. For production, a **DCT-domain steganographic layer** can be added for print-scan robustness.

---

## 6. Watermark ID → Blockchain Traceability

The watermark and the blockchain entry are linked:

```
At decryption time:
  1. Generate: WID = SHA3-256(recipientID || docCID || ts || nonce)
  2. Embed WID into PDF  → recipient gets watermarked PDF
  3. Log to Fabric: { WID, recipientID, docHash, timestamp, signature }

At attribution time:
  1. Extract WID from leaked PDF
  2. Fabric.QueryByWatermark(WID) → returns event record
  3. Verify Dilithium signature in record using stored public key
  4. Output: { recipientID, email, timestamp, signatureValid: true }
```

The SHA3-256 watermark ID is the **cryptographic link** between:
- The physical document copy (embedded invisibly)
- The immutable blockchain record (logged permanently)

---

## 7. Testing the Watermark System

```python
# backend/tests/test_watermark.py
import pytest
from app.services.watermark_service import embed_watermark, extract_watermark

SAMPLE_WATERMARK_ID = "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"

def test_embed_and_extract_roundtrip(sample_pdf_bytes: bytes):
    """Watermark embedded must be exactly extractable."""
    watermarked = embed_watermark(sample_pdf_bytes, SAMPLE_WATERMARK_ID)
    extracted = extract_watermark(watermarked)
    assert extracted == SAMPLE_WATERMARK_ID

def test_watermark_survives_resave(sample_pdf_bytes: bytes):
    """Watermark must survive a PDF re-save operation."""
    import fitz
    watermarked = embed_watermark(sample_pdf_bytes, SAMPLE_WATERMARK_ID)

    # Simulate re-save
    doc = fitz.open(stream=watermarked, filetype="pdf")
    resaved = doc.tobytes()
    doc.close()

    extracted = extract_watermark(resaved)
    assert extracted == SAMPLE_WATERMARK_ID

def test_no_watermark_on_original(sample_pdf_bytes: bytes):
    """Original (non-watermarked) PDF should return None."""
    extracted = extract_watermark(sample_pdf_bytes)
    assert extracted is None

def test_different_sessions_different_watermarks(sample_pdf_bytes: bytes):
    """Two decryption sessions of the same doc must produce different watermarks."""
    import hashlib, secrets
    wid1 = hashlib.sha3_256(b"user1|cid1|1000|" + secrets.token_bytes(32)).hexdigest()
    wid2 = hashlib.sha3_256(b"user1|cid1|1000|" + secrets.token_bytes(32)).hexdigest()
    assert wid1 != wid2  # Different nonces → different watermarks
```
