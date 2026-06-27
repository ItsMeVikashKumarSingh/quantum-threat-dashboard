import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.main import app
from src.database import Base, get_db
from src.scanner import analyze_raw_text

# Use a temporary SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_temp.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_dashboard_route():
    response = client.get("/")
    assert response.status_code == 200
    assert "Quantum Threat Registry" in response.text

def test_scanner_engine_regex():
    text = "const cipher = md5(password); algorithm='3des';"
    results = analyze_raw_text(text, "config_file.js")
    assert len(results) >= 2
    algos = [r["detected_algorithm"] for r in results]
    assert "MD5" in algos
    assert "3DES" in algos
    assert all(r["threat_level"] == "High" for r in results)

def test_sandbox_encrypt_route():
    response = client.post(
        "/sandbox/encrypt",
        data={"text_payload": "secure payment info", "pqc_algorithm": "ML-KEM-768"}
    )
    assert response.status_code == 200
    assert "Content-Disposition" in response.headers
    assert "package_sandbox_data.txt.pqc" in response.headers["Content-Disposition"]
    
    package = response.json()
    assert package["pqc_algorithm_selected"] == "ML-KEM-768"
    assert "simulated_encapsulated_ciphertext_hex" in package
    assert "simulated_digital_signature_hex" in package
