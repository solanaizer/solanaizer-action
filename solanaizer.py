import os
from ai_validator import analyze
from pathlib import Path
import json

API_KEY = os.environ["OPENAPI_TOKEN"]


def validate(file_path: Path):
    """Checking files for vulnerabilities"""
    if file_path.suffix != ".rs":
        print("Not a Rust file.")
        return

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    try:
        return analyze(API_KEY, content, file_path)
    except:
        return []


def get_files(directory):
    """Getting all the rust files in the directory"""
    files = []
    for root, _, filenames in os.walk(directory):
        for fn in filenames:
            if fn.endswith(".rs"):
                files.append(os.path.join(root, fn))
    return files


if __name__ == "__main__":
    DIR_TO_SEARCH = "programs/"

    rust_files = get_files(DIR_TO_SEARCH)

    json_dumps = []

    for rust_file in rust_files:
        path = Path(rust_file)
        json_dumps += validate(path)

    print(json.dumps(json_dumps))
