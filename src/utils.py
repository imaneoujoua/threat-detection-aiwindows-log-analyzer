import logging
import json

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger("CyberShield")

def print_header(text):
    print("\n" + "=" * 50)
    print(text)
    print("=" * 50)

def print_success(text):
    print(f"[SUCCESS] {text}")

def print_error(text):
    print(f"[ERROR] {text}")

def print_info(text):
    print(f"[INFO] {text}")

def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
