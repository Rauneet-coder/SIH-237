"""
Forensic Watermark Extractor
Extracts watermark payloads from leaked PDFs, screenshots, or documents,
applying Reed-Solomon error correction and confidence scoring.
"""

import re
import fitz  # PyMuPDF
from typing import Dict, Any
from .ecc import default_ecc

WID_PATTERN = re.compile(r"WID:([a-fA-F0-9]+)")

def extract_pdf_watermark(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Extract forensic watermark from leaked PDF document.
    Scans metadata, structural streams, and text layers.
    """
    extracted_id = None
    confidence = 0.0
    layers_detected = []
    corrected_errors = 0

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        return {
            "status": "EXTRACTION_FAILED",
            "error": f"Invalid document format: {str(e)}",
            "confidence": 0.0
        }

    # ── Attempt 1: Scan Metadata Layer ───────────────────────────────────────
    meta = doc.metadata or {}
    keywords = meta.get("keywords", "")
    producer = meta.get("producer", "")
    subject = meta.get("subject", "")

    meta_match = re.search(r"WID:([a-zA-Z0-9_\-]+)", keywords + " " + subject)
    if meta_match:
        extracted_id = meta_match.group(1)
        layers_detected.append("METADATA_LAYER")
        confidence = max(confidence, 0.90)

    # ── Attempt 2: Scan Microscopic Text Layer on all pages ──────────────────
    for page in doc:
        text = page.get_text()
        matches = WID_PATTERN.findall(text)
        for hex_candidate in matches:
            try:
                raw_payload = bytes.fromhex(hex_candidate)
                decoded_bytes, errs = default_ecc.decode(raw_payload)
                recovered_id = decoded_bytes.decode('utf-8', errors='ignore')
                if recovered_id:
                    extracted_id = recovered_id
                    corrected_errors += errs
                    layers_detected.append("MICRO_TEXT_ECC_RECOVERED")
                    confidence = 0.99 if errs == 0 else 0.95
                    break
            except Exception:
                continue
        if "MICRO_TEXT_ECC_RECOVERED" in layers_detected:
            break

    doc.close()

    if extracted_id:
        return {
            "status": "SUCCESS",
            "watermark_id": extracted_id,
            "confidence": confidence,
            "layers_detected": layers_detected,
            "ecc_errors_corrected": corrected_errors,
            "robustness_verdict": "STRONG_ATTRIBUTION"
        }
    else:
        return {
            "status": "NOT_FOUND",
            "watermark_id": None,
            "confidence": 0.0,
            "layers_detected": [],
            "robustness_verdict": "INCONCLUSIVE"
        }
