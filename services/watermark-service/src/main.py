"""
SIH-237 Forensic Watermarking & Robustness Microservice
FastAPI Application Entrypoint
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
import time
import base64
from typing import Optional, List

from .embedder import embed_pdf_watermark
from .extractor import extract_pdf_watermark
from .transforms import apply_transformations

app = FastAPI(
    title="SIH237 Forensic Watermark Service",
    description="Multi-layer imperceptible forensic watermarking and leak attribution engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check for service monitoring and container readiness"""
    return {
        "status": "ok",
        "service": "SIH237-Watermark-Engine",
        "runtime": "Python 3.11",
        "timestamp": time.time(),
        "capabilities": [
            "PDF_METADATA_EMBED",
            "MICRO_TEXT_ECC_EMBED",
            "TRANSFORMATION_SIMULATOR",
            "CONFIDENCE_EVALUATOR"
        ]
    }

@app.post("/embed")
async def embed_watermark_endpoint(
    file: UploadFile = File(...),
    watermark_id: str = Form(...),
    session_id: str = Form("")
):
    """
    Embed forensic watermark into an uploaded document.
    Returns the watermarked PDF file stream with diagnostic headers.
    """
    try:
        content = await file.read()
        watermarked_bytes, report = embed_pdf_watermark(content, watermark_id, session_id)

        headers = {
            "Content-Disposition": f"attachment; filename=watermarked_{file.filename}",
            "X-Watermark-ID": watermark_id,
            "X-Watermark-Status": report["status"],
            "X-Watermark-Layers": ",".join(report["layers_applied"])
        }

        return Response(
            content=watermarked_bytes,
            media_type="application/pdf",
            headers=headers
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Watermark embedding failed: {str(e)}")

@app.post("/extract")
async def extract_watermark_endpoint(
    file: UploadFile = File(...)
):
    """
    Extract forensic watermark and session fingerprint from a leaked document.
    """
    try:
        content = await file.read()
        result = extract_pdf_watermark(content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Watermark extraction failed: {str(e)}")

@app.post("/simulate-transforms")
async def simulate_transforms_endpoint(
    file: UploadFile = File(...),
    transforms: str = Form("jpeg_compress,blur")
):
    """
    Simulate real-world leak attacks (JPEG compression, blur, crop, camera simulation).
    """
    try:
        content = await file.read()
        transform_list = [t.strip() for t in transforms.split(",") if t.strip()]
        transformed_bytes = apply_transformations(content, transform_list)

        return Response(
            content=transformed_bytes,
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=transformed.png"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transformation simulation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8001, reload=True)
