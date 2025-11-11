import os

def load_email(path: str) -> bytes:
    """
    Load a raw .eml email file and return its byte content.
    
    Args:
        path (str): The path to the .eml file.
    
    Returns:
        bytes: The raw content of the email file.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is empty or not an .eml file.
        IOError: If there is an error reading the file.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"[ERROR] File not found: {path}")

    if not path.lower().endswith(".eml"):
        raise ValueError(f"[ERROR] Invalid file type. Expected a .eml file: {path}")

    try:
        with open(path, 'rb') as file:
            raw_email = file.read()
            if not raw_email:
                raise ValueError(f"[ERROR] The file is empty: {path}")
    except OSError as e:
        raise IOError(f"[ERROR] Failed to read file: {e}")
    
    return raw_email

# Optional CLI usage for testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load and display raw .eml content.")
    parser.add_argument("path", type=str, help="Path to .eml file")
    args = parser.parse_args()

    try:
        content = load_email(args.path)
        print(f"[INFO] Successfully loaded {len(content)} bytes from: {args.path}")
        print("=" * 40)
        print(content.decode(errors='replace'))  # print raw email, decode to see text
    except (FileNotFoundError, ValueError, IOError) as e:
        print(e)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

