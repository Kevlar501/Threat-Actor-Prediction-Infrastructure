import os
import hashlib
import requests
import json

# Configuration
DATA_DIR = "data"
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
VERSION = "v19.2"
# SHA-256 checksum for enterprise-attack-19.2.json (from GitHub release)
EXPECTED_CHECKSUM = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
GITHUB_RELEASE_URL = "https://github.com/mitre-attack/attack-stix-data/releases/download/v19.2/enterprise-attack.json"

def create_directories():
    """Ensure data directories exist."""
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

def download_file(url, filepath):
    """Download file with progress indication."""
    print(f"Downloading {url}...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(filepath, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"Downloaded to {filepath}")

def verify_checksum(filepath, expected_checksum):
    """Verify file integrity using SHA-256."""
    print(f"Verifying SHA-256 checksum for {filepath}...")
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    actual_checksum = sha256_hash.hexdigest()
    if actual_checksum == expected_checksum:
        print(f"Checksum verified: {actual_checksum}")
        return True
    else:
        print(f"Checksum mismatch! Expected: {expected_checksum}, Got: {actual_checksum}")
        return False

def create_manifest(filepath):
    """Create a MANIFEST.md file with download details."""
    manifest_path = os.path.join(RAW_DIR, "MANIFEST.md")
    with open(filepath, 'rb') as f:
        sha256_hash = hashlib.sha256(f.read()).hexdigest()
    
    manifest_content = f"""# Data Manifest

## MITRE ATT&CK STIX Data
- **Version:** {VERSION}
- **Download Date:** $(date -u)
- **File:** enterprise-attack.json
- **SHA-256 Checksum:** {sha256_hash}
- **Source:** https://github.com/mitre-attack/attack-stix-data/releases/tag/{VERSION}
"""
    with open(manifest_path, 'w') as f:
        f.write(manifest_content)
    print(f"Manifest created at {manifest_path}")

def main():
    create_directories()
    filepath = os.path.join(RAW_DIR, "enterprise-attack.json")
    
    # Download if file doesn't exist
    if not os.path.exists(filepath):
        download_file(GITHUB_RELEASE_URL, filepath)
    else:
        print(f"File already exists at {filepath}. Skipping download.")
    
    # Verify checksum
    if verify_checksum(filepath, EXPECTED_CHECKSUM):
        create_manifest(filepath)
        print("Data acquisition complete and verified.")
    else:
        print("ERROR: Checksum verification failed. Do not proceed with processing.")
        exit(1)

if __name__ == "__main__":
    # You'll need to install requests: pip install requests
    main()