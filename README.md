# Malware Vault

**Malware Vault** is a clean, professional web application built with **FastAPI** and **Tailwind CSS** designed for security analysts, researchers, and students to safely collect, store, inspect, and share malware and virus samples for educational and analysis purposes.

The application features strict containment mechanisms to disarm malware payloads at rest and prevent accidental execution or spread on the server and host machines.

---

## Features

- **Dashboard Repository:** View all quarantined malware samples with associated threat classifications, sample formats, upload timestamps, and cryptographic hashes.
- **Detailed Sample Views:** Inspect technical analysis notes, description summaries, file sizes, and full SHA-256 / MD5 cryptographic hashes.
- **Local Assets & Offline Capable:** Built with locally self-hosted Tailwind CSS (`static/css/tailwind.min.css`) without relying on external CDNs or third-party web services.
- **Safety & Containment Protocol:**
  - **At-Rest Disarming:** Uploaded binary payloads are automatically XOR-obfuscated (`0x5A`) and assigned a `.quarantine` extension upon saving to disk so that they remain inert and non-executable binaries on the server filesystem.
  - **Restricted File System Permissions:** Vault storage directories and files enforce strict file mode permissions (`0600` / `0700`).
  - **Path Traversal Protection:** Sanitize path inputs to prevent directory traversal attacks.
  - **Safe Download Headers:** Sample downloads enforce non-executable response headers (`Content-Disposition: attachment; filename="sample.bin"`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`) to prevent browser execution or accidental launches.
  - **Deduplication:** Automatic SHA-256 check prevents duplicate upload of identical payloads.

---

## Tech Stack

- **Backend Framework:** [FastAPI](https://fastapi.tiangolo.com/) (Python 3.12+)
- **Server:** [Uvicorn](https://www.uvicorn.org/)
- **Database:** SQLite3
- **Templating:** Jinja2
- **Frontend Styling:** Tailwind CSS (locally hosted)

---

## Installation & Setup

### 1. Prerequisites

Ensure Python 3.10+ and `pip` are installed on your machine.

```bash
python3 --version
```

### 2. Clone Repository & Install Dependencies

```bash
git clone <repository-url>
cd rootBox

pip install fastapi uvicorn jinja2 python-multipart pytest httpx
```

### 3. Run Application Server

Start the application with Uvicorn:

```bash
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser and navigate to:
`http://localhost:8000`

---

## Usage Guide

1. **View Dashboard:** Navigate to `http://localhost:8000` to view all quarantined samples.
2. **Upload Sample:**
   - Click **Upload Sample** in the navigation bar.
   - Select the malware/virus file payload.
   - Choose threat classification (e.g., Ransomware, Trojan, Worm, Spyware, Rootkit, EICAR Test Sample).
   - Provide file format (e.g., PE32 Executable, ELF64, APK, Script).
   - Enter optional descriptions and technical analysis/IoC notes.
   - Click **Upload to Vault**.
3. **Inspect Sample:** Click **View Details** on any sample to examine full hashes, properties, and notes.
4. **Download Raw Payload:** Click **Download Raw Binary** on the sample details page or dashboard. The server will deobfuscate the payload on-the-fly and send it as a safe non-executable attachment download.

---

## Running Tests

Run the test suite using `pytest`:

```bash
PYTHONPATH=. pytest tests/
```

---

## Project Structure

```
├── app/
│   ├── database.py   # SQLite connection and table creation
│   ├── main.py       # FastAPI application routes
│   ├── models.py     # Pydantic models & schemas
│   └── vault.py      # Core vault containment, XOR disarming & hashing logic
├── static/
│   └── css/
│       └── tailwind.min.css # Locally hosted Tailwind CSS
├── templates/
│   ├── base.html     # Base layout with navigation and footer
│   ├── detail.html   # Sample detailed analysis view
│   ├── index.html    # Dashboard listing quarantined samples
│   └── upload.html   # Sample upload form page
├── tests/
│   ├── test_api.py   # Integration tests for FastAPI endpoints
│   └── test_vault.py # Unit tests for storage containment & disarming logic
├── LICENSE           # MIT License
└── README.md         # Project documentation
```

---

## License

This project is licensed under the [MIT License](LICENSE).
