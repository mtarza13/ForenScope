# Welcome to EviForge

**EviForge** is a professional, offline-first digital forensics platform designed for defensive security operations.

## Key Features

- **Offline-First**: No data leaves your machine. Evidence is stored in a local "Vault".
- **Defensible**: Strict Chain-of-Custody logging and hash verification.
- **Modular**: Run various forensic modules (inventory, timeline, strings, etc.) on your evidence.
- **Secure**: Application auditing and "Authorized Use Only" gates.

## Getting Started

Check out the [Quickstart](index.md#quickstart) guide to spin up the platform.

### Quickstart

1.  **Clone & Build**:
    ```bash
    git clone https://github.com/mtarza13/ForenScope.git
    cd ForenScope
    docker compose up -d --build
    ```

2.  **Login**:
    Navigate to `http://localhost/web`.
    Default Creds: `admin` / `admin`.

3.  **Start an Investigation**:
    - Create a **Case**.
    - **Ingest** evidence from the `import/` directory.
    - Run **Modules** to analyze artifacts.
