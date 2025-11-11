import hashlib

def compute_sha256(data: bytes) -> str:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

def compute_md5(data: bytes) -> str:
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    return md5_hash.hexdigest()

def compute_hashes(file_path: str):
    """Compute MD5 and SHA256 of a file path."""
    with open(file_path, "rb") as f:
        data = f.read()
    return {"md5": compute_md5(data), "sha256": compute_sha256(data)}

def compute_hashes_from_bytes(data: bytes):
    """Compute MD5 and SHA256 from in-memory bytes."""
    return {"md5": compute_md5(data), "sha256": compute_sha256(data)}
