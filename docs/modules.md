# Forensic Modules

EviForge includes a suite of verified forensic modules.

## Core Modules

### 1. Inventory
- **Goal**: Catalog all files in the evidence image.
- **Output**: JSON/CSV list with MD5/SHA256 hashes.
- **Status**: ✅ Active

### 2. Timeline (MACE)
- **Goal**: Extract Modified, Accessed, Created, Entry times.
- **Output**: Chronological event list.
- **Status**: ✅ Active

### 3. Strings
- **Goal**: Extract printable ASCII/Unicode strings.
- **Output**: JSON with offset and string content.
- **Status**: ✅ Active

### 4. Exif Metadata
- **Goal**: Extract Exif/IPTC/XMP metadata from images.
- **Output**: JSON dictionary.
- **Status**: ✅ Active

### 5. Parse Text (Tika)
- **Goal**: Extract text content from PDF, DOCX, HTML, etc.
- **Output**: Plain text and metadata.
- **Status**: ✅ Active

### 6. Triage
- **Goal**: Assess file entropy and type integrity (Magic vs Extension).
- **Output**: Risk score and anomaly flags.
- **Status**: ✅ Active
