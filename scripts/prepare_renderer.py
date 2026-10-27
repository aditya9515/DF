"""Provision isolated LibreOffice files; never installs or modifies desktop Office."""

from pathlib import Path
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def retrieve(url, path):
    if path.exists():
        return
    print("Downloading", path.name, flush=True)
    with (
        urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "AgentForensics/1.0"}), timeout=120
        ) as r,
        path.with_suffix(".part").open("wb") as f,
    ):
        while b := r.read(8 * 1024 * 1024):
            f.write(b)
    path.with_suffix(".part").replace(path)


if __name__ == "__main__":
    dest = ROOT / ".tools/renderer"
    dest.mkdir(parents=True, exist_ok=True)
    retrieve(
        "https://github.com/activescott/lessmsi/releases/download/v2.12.9/lessmsi-v2.12.9.zip", dest / "lessmsi.zip"
    )
    with zipfile.ZipFile(dest / "lessmsi.zip") as z:
        z.extractall(dest / "lessmsi")
    retrieve(
        "https://download.documentfoundation.org/libreoffice/stable/26.8.1/win/x86_64/LibreOffice_26.8.1_Win_x86-64.msi",
        dest / "LibreOffice.msi",
    )
    tool = next((dest / "lessmsi").rglob("lessmsi.exe"))
    subprocess.run([str(tool), "x", str(dest / "LibreOffice.msi"), str(dest / "office") + "\\"], check=True)
    executable = next((dest / "office").rglob("soffice.exe"))
    print("ISOLATED_SOFFICE=" + str(executable), flush=True)
