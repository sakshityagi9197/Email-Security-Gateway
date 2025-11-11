import os
import shutil
import tempfile
from pathlib import Path


# Load .eml from folder isnto memory
def load_latest_eml():
    folder = str(Path.home() / "Downloads")  # Auto-pick Downloads
    emls = list(Path(folder).glob("*.eml"))
    if not emls:
        print(" No .eml files found.")
        return None, None
    latest = max(emls, key=os.path.getmtime)
    with open(latest, 'rb') as f:
        content = f.read()
    return latest.name, content

# Save content to temp file
def save_temp_eml(content: bytes) -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml", mode='wb') as temp_file:
        temp_file.write(content)
        return temp_file.name

# Move clean emails to `storage/unthreat/`
def move_to_unthreat(temp_path: str, original_name: str):
    dest_folder = Path("storage/unthreat")
    dest_folder.mkdir(parents=True, exist_ok=True)
    dest_path = dest_folder / original_name
    shutil.move(temp_path, dest_path)
    print(f" Moved to clean folder: {dest_path}")

# ----------- MAIN ----------
filename, eml_content = load_latest_eml()

if eml_content:
    print(f" Loaded {filename}, size: {len(eml_content)} bytes")

    temp_path = save_temp_eml(eml_content)
    print(f" Temp file created at: {temp_path}")

    if is_email_malicious(eml_content):
        print(" Malicious email detected! Deleting temp file.")
        os.remove(temp_path)
    else:
        move_to_unthreat(temp_path, filename)
        print(" Email is clean and preserved.")
else:
    print(" Skipping — no email loaded.")

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