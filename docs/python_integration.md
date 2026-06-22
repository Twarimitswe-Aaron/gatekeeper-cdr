# Gatekeeper Python / FastAPI Integration Guide

This guide demonstrates how to intercept an incoming file upload in a Python FastAPI backend, sanitize the file in-memory using the `gatekeeper-cdr` PyO3 bindings, and securely save it.

## 1. Installation

```bash
pip install gatekeeper-cdr
# If using FastAPI:
pip install fastapi python-multipart uvicorn
```

## 2. FastAPI Integration Example

FastAPI provides an `UploadFile` object. We will read the file into memory as `bytes`, pass those bytes to the native Rust engine, and return the safe file.

```python
from fastapi import FastAPI, UploadFile, File, HTTPException
import gatekeeper_cdr

app = FastAPI()

@app.post("/upload")
async def upload_document(file: UploadFile = File(...)):
    # Read the raw, untrusted bytes into memory
    raw_bytes = await file.read()
    
    try:
        # 🛡️ ZERO-TRUST SANITIZATION 🛡️
        # Strictly expect a "pdf". Will reject if the file is an image/executable.
        result = gatekeeper_cdr.disarm(raw_bytes, expected_format="pdf")
        
        # Telemetry
        mb_received = result.original_size_bytes / (1024 * 1024)
        mb_output = result.final_size_bytes / (1024 * 1024)
        print(f"Sanitized {result.detected_format}: {mb_received:.2f} MB -> {mb_output:.2f} MB")
        
    except ValueError as e:
        # The Rust engine throws a ValueError if the file is completely unrecognized,
        # structurally corrupted, or if there is a FormatMismatch.
        raise HTTPException(
            status_code=406, 
            detail=f"Rejected: Invalid or malicious file structure. {str(e)}"
        )
    
    # Save the sanitized file
    safe_path = f"./uploads/safe_{file.filename}"
    with open(safe_path, "wb") as out_file:
        out_file.write(result.buffer)
        
    return {
        "message": "File successfully sanitized and saved.",
        "safe_path": safe_path
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## How It Works
- **Zero-Copy Overheads:** The `PyO3` binding natively translates the Python `bytes` object directly to a Rust `&[u8]` slice without heavy copying.
- **Strict Error Handling:** Gatekeeper will intentionally crash the sanitization process (throwing a handled exception) rather than silently returning a potentially malicious file.
