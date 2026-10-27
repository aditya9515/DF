import os
from pathlib import Path
import subprocess
import sys
import time
import httpx
from .common import ROOT, file_hash, save_json

MODEL = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"


def doctor(root=ROOT):
    root = Path(root)
    result = {
        "python": sys.version,
        "root": str(root),
        "model_present": (root / ".models" / MODEL).exists(),
        "runtime_present": bool(list((root / ".tools/llama").rglob("llama-server.exe")))
        if (root / ".tools/llama").exists()
        else False,
    }
    try:
        result["gpu"] = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        result["gpu"] = "No NVIDIA GPU available; CPU profile supported"
    try:
        result["server_ready"] = httpx.get("http://127.0.0.1:8081/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        result["server_ready"] = False
    return result


def fetch_model(root=ROOT):
    subprocess.run([sys.executable, str(Path(root) / "scripts/download_assets.py")], check=True)


def serve_model(root=ROOT, gpu_layers=24, background=False):
    root = Path(root)
    model = root / ".models" / MODEL
    candidates = sorted((root / ".tools/llama").rglob("llama-server.exe"))
    if not candidates or not model.exists():
        raise FileNotFoundError("Run fetch-model first")
    info = {
        "model": "Qwen3-4B-Instruct-2507",
        "quantization": "Q4_K_M",
        "repository": "unsloth/Qwen3-4B-Instruct-2507-GGUF",
        "revision": "a06e946bb6b655725eafa393f4a9745d460374c9",
        "sha256": file_hash(model),
        "runtime": "llama.cpp b11900",
        "context_tokens": 4096,
        "gpu_layers": gpu_layers,
        "parallel_sessions": 1,
        "endpoint": "http://127.0.0.1:8081/v1",
        "hardware": doctor(root),
    }
    if info["sha256"] != "3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597":
        raise ValueError("Model checksum mismatch")
    save_json(root / "configs/model.json", info)
    command = [
        str(candidates[0]),
        "-m",
        str(model),
        "--host",
        "127.0.0.1",
        "--port",
        "8081",
        "--alias",
        "local-qwen",
        "-c",
        "4096",
        "-np",
        "1",
        "-ngl",
        str(gpu_layers),
        "--jinja",
        "--no-webui",
        "--flash-attn",
        "on",
    ]
    if not background:
        return subprocess.run(command, cwd=candidates[0].parent).returncode
    logdir = root / "tmp/runtime"
    logdir.mkdir(parents=True, exist_ok=True)
    with (logdir / "server.log").open("ab") as log:
        proc = subprocess.Popen(
            command,
            cwd=candidates[0].parent,
            stdout=log,
            stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    save_json(root / ".private/server.json", {"pid": proc.pid, "command": command})
    for _ in range(90):
        if proc.poll() is not None:
            raise RuntimeError(f"Model server exited {proc.returncode}; inspect tmp/runtime/server.log")
        try:
            if httpx.get("http://127.0.0.1:8081/health", timeout=2).status_code == 200:
                return {"pid": proc.pid, "ready": True}
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise TimeoutError("Model server did not become ready; inspect tmp/runtime/server.log")
