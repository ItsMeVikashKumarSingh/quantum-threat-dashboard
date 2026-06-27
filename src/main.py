from fastapi import FastAPI, Request, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import os
import io
import json
import hashlib
from src.database import get_db, init_db, ScannedAsset, MigrationHistory, SessionLocal
from src.scanner import analyze_crypto_file, analyze_raw_text

app = FastAPI(title="Quantum Threat Assessment Dashboard")

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()
    db = SessionLocal()
    try:
        if db.query(ScannedAsset).count() == 0:
            demo_assets = [
                ScannedAsset(name="RTGS_Transaction_Broker", asset_type="API Endpoint", detected_algorithm="RSA-1024", key_size=1024, threat_level="High"),
                ScannedAsset(name="User_Credentials_Hash", asset_type="Database Column", detected_algorithm="MD5", key_size=None, threat_level="High"),
                ScannedAsset(name="Active_Admin_Session_Token", asset_type="Configuration File", detected_algorithm="RC4", key_size=None, threat_level="High"),
                ScannedAsset(name="Payment_Gateway_TLS_Cert", asset_type="Cryptographic Key", detected_algorithm="RSA-2048", key_size=2048, threat_level="Medium"),
                ScannedAsset(name="Ledger_Database_Backups", asset_type="File System", detected_algorithm="AES-256", key_size=256, threat_level="Medium")
            ]
            db.add_all(demo_assets)
            db.commit()
    finally:
        db.close()

# Setup templates
templates = Jinja2Templates(directory="src/templates")

@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    assets = db.query(ScannedAsset).all()
    migrations = db.query(MigrationHistory).all()
    
    # Calculate statistics
    total_assets = len(assets)
    high_threat = sum(1 for a in assets if a.threat_level == "High")
    medium_threat = sum(1 for a in assets if a.threat_level == "Medium")
    low_threat = sum(1 for a in assets if a.threat_level == "Low")
    
    migrated_count = db.query(MigrationHistory).filter(MigrationHistory.migration_status == "Migrated").count()
    
    # Calculate estimated quantum risk metrics
    quantum_risk_score = 0
    if total_assets > 0:
        quantum_risk_score = int(((high_threat * 1.0 + medium_threat * 0.5) / total_assets) * 100)
    
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "assets": assets,
            "migrations": migrations,
            "total_assets": total_assets,
            "high_threat": high_threat,
            "medium_threat": medium_threat,
            "low_threat": low_threat,
            "migrated_count": migrated_count,
            "quantum_risk_score": quantum_risk_score,
        }
    )

@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    results = analyze_crypto_file(content, file.filename)
    
    if not results:
        # If no legacy cryptographic elements are found, register as low threat
        new_asset = ScannedAsset(
            name=file.filename,
            asset_type="File Upload",
            detected_algorithm="None (Secure/Unknown)",
            key_size=None,
            threat_level="Low"
        )
        db.add(new_asset)
    else:
        for r in results:
            new_asset = ScannedAsset(
                name=r["name"],
                asset_type=r["asset_type"],
                detected_algorithm=r["detected_algorithm"],
                key_size=r["key_size"],
                threat_level=r["threat_level"]
            )
            db.add(new_asset)
            
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/scan/mock")
def scan_mock(
    asset_name: str = Form(...),
    asset_type: str = Form(...),
    detected_algorithm: str = Form(...),
    key_size: int = Form(None),
    db: Session = Depends(get_db)
):
    # Classify threat levels based on algorithm
    if detected_algorithm in ["MD5", "SHA-1", "DES", "3DES", "RC4", "RSA-1024"]:
        threat = "High"
    elif detected_algorithm in ["RSA-2048", "RSA-4096", "AES-128", "AES-256", "ECDSA-nistp256", "ECDH-nistp256"]:
        threat = "Medium"
    else:
        threat = "Low"
        
    new_asset = ScannedAsset(
        name=asset_name,
        asset_type=asset_type,
        detected_algorithm=detected_algorithm,
        key_size=key_size,
        threat_level=threat
    )
    db.add(new_asset)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/migrate/{asset_id}")
def migrate_asset(asset_id: int, target_algorithm: str = Form(...), db: Session = Depends(get_db)):
    asset = db.query(ScannedAsset).filter(ScannedAsset.id == asset_id).first()
    if asset:
        # Record migration event
        new_migration = MigrationHistory(
            asset_id=asset.id,
            target_algorithm=target_algorithm,
            migration_status="Migrated"
        )
        db.add(new_migration)
        
        # Update asset record to Low risk (quantum-safe)
        asset.threat_level = "Low"
        asset.detected_algorithm = f"{asset.detected_algorithm} -> {target_algorithm}"
        db.commit()
        
    return RedirectResponse(url="/", status_code=303)

@app.post("/reset")
def reset_database(db: Session = Depends(get_db)):
    db.query(MigrationHistory).delete()
    db.query(ScannedAsset).delete()
    
    # Seed standard initial data for testing
    demo_assets = [
        ScannedAsset(name="RTGS_Transaction_Broker", asset_type="API Endpoint", detected_algorithm="RSA-1024", key_size=1024, threat_level="High"),
        ScannedAsset(name="User_Credentials_Hash", asset_type="Database Column", detected_algorithm="MD5", key_size=None, threat_level="High"),
        ScannedAsset(name="Active_Admin_Session_Token", asset_type="Configuration File", detected_algorithm="RC4", key_size=None, threat_level="High"),
        ScannedAsset(name="Payment_Gateway_TLS_Cert", asset_type="Cryptographic Key", detected_algorithm="RSA-2048", key_size=2048, threat_level="Medium"),
        ScannedAsset(name="Ledger_Database_Backups", asset_type="File System", detected_algorithm="AES-256", key_size=256, threat_level="Medium")
    ]
    db.add_all(demo_assets)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/sandbox/encrypt")
async def sandbox_encrypt(
    text_payload: str = Form(None),
    file_payload: UploadFile = File(None),
    pqc_algorithm: str = Form("ML-KEM-768")
):
    data = b""
    filename = "sandbox_data.txt"
    if file_payload and file_payload.filename:
        data = await file_payload.read()
        filename = file_payload.filename
    elif text_payload:
        data = text_payload.encode("utf-8")
        
    if not data:
        data = b"No payload content provided"
        
    # Generate cryptographic simulation output using stable hashing
    seed = hashlib.sha256(data).digest()
    ciphertext_hex = hashlib.sha256(seed + b"ciphertext").hexdigest()[:64]
    shared_secret_hex = hashlib.sha256(seed + b"secret").hexdigest()[:64]
    public_key_hex = hashlib.sha256(seed + b"pubkey").hexdigest()[:64]
    signature_hex = hashlib.sha256(seed + b"signature").hexdigest()[:128]
    
    package_data = {
        "pqc_algorithm_selected": pqc_algorithm,
        "payload_sha256_hash": hashlib.sha256(data).hexdigest(),
        "simulated_encapsulated_ciphertext_hex": ciphertext_hex,
        "simulated_shared_secret_hex": shared_secret_hex,
        "simulated_signer_public_key_hex": public_key_hex,
        "simulated_digital_signature_hex": signature_hex,
        "original_payload_preview": data[:150].decode("utf-8", errors="ignore")
    }
    
    serialized = json.dumps(package_data, indent=2).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(serialized),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=package_{filename}.pqc"}
    )
