"""Pinned, checksum-verified local inference assets; no installer or admin access."""

import argparse
import concurrent.futures
import hashlib
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODEL_REV = "a06e946bb6b655725eafa393f4a9745d460374c9"
MODEL_FILE = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
ASSETS = {
    "model": (
        f"https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/{MODEL_REV}/{MODEL_FILE}",
        ROOT / ".models" / MODEL_FILE,
        "3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597",
    ),
    "runtime": (
        "https://github.com/ggml-org/llama.cpp/releases/download/b11900/llama-b11900-bin-win-cuda-12.4-x64.zip",
        ROOT / ".tools/llama.zip",
        "387ad76c926cdb301971851a11df018165a7b4df4b1b7c64cf4b09a367ec82bc",
    ),
    "cuda": (
        "https://github.com/ggml-org/llama.cpp/releases/download/b11900/cudart-llama-bin-win-cuda-12.4-x64.zip",
        ROOT / ".tools/cuda.zip",
        "8c79a9b226de4b3cacfd1f83d24f962d0773be79f1e7b75c6af4ded7e32ae1d6",
    ),
}


def digest(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def download(name):
    url, path, expected = ASSETS[name]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and digest(path) == expected:
        print(f"{name}: verified cached file", flush=True)
    else:
        part = path.with_suffix(path.suffix + ".part")
        print(f"{name}: downloading pinned asset", flush=True)
        req = urllib.request.Request(url, headers={"User-Agent": "AgentForensics/1.0"})
        with urllib.request.urlopen(req, timeout=120) as source, open(part, "wb") as target:
            size = int(source.headers.get("Content-Length", 0))
            done = 0
            last = -1
            while block := source.read(8 * 1024 * 1024):
                target.write(block)
                done += len(block)
                progress = int(100 * done / size) if size else done // (100 * 1024 * 1024)
                if progress // 10 != last:
                    print(f"{name}: {done / 1e6:.0f} MB / {size / 1e6:.0f} MB", flush=True)
                    last = progress // 10
        actual = digest(part)
        if actual != expected:
            raise ValueError(f"Checksum mismatch for {name}: {actual}")
        part.replace(path)
    if name != "model":
        dest = ROOT / ".tools/llama"
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                resolved = (dest / member.filename).resolve()
                if not resolved.is_relative_to(dest.resolve()):
                    raise ValueError("Unsafe archive entry")
            archive.extractall(dest)
    return str(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("assets", nargs="*", default=list(ASSETS))
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for path in pool.map(download, args.assets):
            print(path, flush=True)
