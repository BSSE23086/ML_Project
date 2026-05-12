"""
Dataset Downloader
Downloads the NSL-KDD dataset from the Canadian Institute for Cybersecurity.
If download fails, the system uses synthetic data automatically.
Authors: Muhammad Tayyab (BSSE23018), Tehreem Mazhar (BSSE23086)

Usage:
    python download_data.py
"""

import os
import urllib.request
import zipfile

# NSL-KDD dataset URLs (from CICIDS / University of New Brunswick)
DATASET_URLS = {
    "KDDTrain+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
    "KDDTest+.txt":  "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
}

DATA_DIR = "data"


def download_dataset():
    """Download NSL-KDD training and test sets."""
    os.makedirs(DATA_DIR, exist_ok=True)

    for filename, url in DATASET_URLS.items():
        dest = os.path.join(DATA_DIR, filename)
        if os.path.exists(dest):
            print(f"[SKIP] {filename} already exists.")
            continue

        print(f"[DOWNLOAD] Downloading {filename}...")
        try:
            urllib.request.urlretrieve(url, dest)
            size = os.path.getsize(dest) / (1024 * 1024)
            print(f"[OK] Saved {filename} ({size:.2f} MB)")
        except Exception as e:
            print(f"[ERROR] Could not download {filename}: {e}")
            print("[INFO] The system will use synthetic data for demo purposes.")


if __name__ == "__main__":
    download_dataset()
    print("\n[DONE] Data directory contents:")
    for f in os.listdir(DATA_DIR):
        print(f"  {f}")
