# Quantum Threat Assessment & Migration Dashboard

A security-oriented evaluation dashboard designed to audit enterprise infrastructure for classical cryptographic vulnerabilities and coordinate post-quantum cryptographic (PQC) migrations. The system scans configurations and X.509/PEM keys, log exposure statuses in a SQLite database, and packages data inside quantum-safe envelopes.

---

## Introduction & Problem Statement

Legacy public-key algorithms (RSA, ECC) and deprecated hash functions (MD5, SHA-1) are highly vulnerable to decryption and forgery under Shor's algorithm. For instance, a quantum computer with a sufficient physical qubit count can factor RSA-1024 or resolve Elliptic Curve Discrete Logarithms in minutes. 

This registry acts as an audit control panel for security engineers to identify where vulnerable algorithms are deployed across databases, file systems, and API endpoints, estimate risk exposure, and orchestrate PQC upgrades.

---

## Workspace Directory Structure

```
quantum-threat-dashboard/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
└── src/
    ├── __init__.py
    ├── main.py
    ├── database/
    │   ├── __init__.py
    │   └── models.py
    ├── scanner/
    │   ├── __init__.py
    │   └── engine.py
    ├── templates/
    │   └── dashboard.html
    └── tests/
        ├── __init__.py
        └── test_dashboard.py
```

---

## Core Features

1.  **Multi-Channel Vulnerability Scanner:**
    *   **Configuration Scanner:** Reads plain text configuration blocks to detect legacy cipher statements (MD5, RC4, DES, 3DES, SHA-1).
    *   **Cryptographic Key Parser:** Dynamically parses uploaded X.509 Certificates or raw PEM keys (Private/Public) using native cryptography modules to determine key size and mathematical curves.
2.  **Audit Logs & SQLite Engine:**
    *   Saves threat exposure records inside an active SQLite backend.
    *   Enables tracking of asset names, types, detected algorithms, key sizes, and risk categories (High, Medium, Low).
3.  **Migration Orchestration Sandbox:**
    *   Provides one-click migration to convert legacy classical assets into quantum-safe standards.
    *   Simulates securing arbitrary inputs or files using a simulated `ML-KEM-768` (key encapsulation) and `ML-DSA-65` (digital signature) pipeline.
    *   Outputs a downloadable `.pqc` JSON container containing simulated encrypted payloads, shared secrets, public keys, and cryptographic signatures.
4.  **Security Dashboards & Timelines:**
    *   Integrates Chart.js to render real-time asset risk distributions.
    *   Includes a logarithmic time-to-crack scale illustrating Shor's algorithm quantum computational speedups.

---

## Installation & Setup

Ensure Python 3.9+ is installed on your local host.

### 1. Local Python Deployment

#### Navigate and Create Environment:
```bash
cd quantum-threat-dashboard
python -m venv venv
```

#### Activate the Environment:
*   **Windows (PowerShell):** `.\venv\Scripts\Activate.ps1`
*   **macOS / Linux:** `source venv/bin/activate`

#### Install Dependencies:
```bash
pip install -r requirements.txt
```

#### Launch the Web Application:
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8001
```
Open `http://localhost:8001` in your browser.

---

### 2. Docker Deployment (Recommended)

1.  Verify Docker Desktop is running on your host system.
2.  Build and run the container:
    ```bash
    docker compose up --build -d
    ```
3.  Open `http://localhost:8001` in your browser.

---

## Resume Bullets

*   **Designed and implemented an Enterprise Cryptographic Threat Dashboard** in Python/FastAPI using SQLite and SQLAlchemy to audit legacy network infrastructure.
*   **Developed a cryptographic file scanner** utilizing native libraries to parse X.509 PEM certificates, extract key types, and flag Shor-vulnerable algorithms.
*   **Engineered an interactive post-quantum cryptographic sandbox** simulating data encapsulation (ML-KEM) and signatures (ML-DSA) with downloadable secure package configurations.
