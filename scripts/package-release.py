"""Package already-published Windows builds; include only source-controlled-shaped server files.

Usage: python3 scripts/package-release.py 0.7.0
Run publish.ps1 or dotnet publish App + Cli to artifacts/portable/win-{x64,arm64} first.
Use --from-archives to validate Windows CI ZIPs and add source/server/checksums.
"""
import hashlib
import json
import re
import shutil
import struct
import sys
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
version = sys.argv[1] if len(sys.argv) in {2, 3} else ""
from_archives = len(sys.argv) == 3 and sys.argv[2] == "--from-archives"
if len(sys.argv) == 3 and not from_archives:
    raise SystemExit("Unknown packaging option")
if not re.fullmatch(r"0\.\d+\.\d+", version):
    raise SystemExit("Supply the release version, e.g. 0.7.0")
if f"<Version>{version}</Version>" not in (root / "src/Sentinel.App/Sentinel.App.csproj").read_text():
    raise SystemExit("Version does not match the application project")
skip = {"bin", "obj", "node_modules", "data", ".git", "__pycache__", ".DS_Store"}
private = {"signing-private.pem", "admin-token.txt", "api-key.dpapi", "vault-key.dpapi"}

def allowed(path):
    return not any(x in skip or x in private or x.startswith(".env") or x.endswith((".dpapi", ".vault")) for x in path.parts)

server_files = [p for p in (root / "server").rglob("*") if p.is_file() and not p.is_symlink() and allowed(p.relative_to(root / "server"))
                and (p.relative_to(root / "server").parts[0] in {"seeds", "test"} or p.parent == root / "server" and
                     (p.suffix == ".mjs" or p.name in {"package.json", "Dockerfile", "compose.yml", "README.md", ".dockerignore"}))]
artifacts = root / "artifacts"
outputs = []

def archive(name, files):
    destination = artifacts / name
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path, member in sorted(files, key=lambda x: x[1]):
            z.write(path, member)
    with zipfile.ZipFile(destination) as z:
        if z.testzip() is not None or any(not allowed(Path(name)) for name in z.namelist()):
            raise RuntimeError("ZIP integrity/content validation failed")
    outputs.append(destination)
    print(f"PASS {name}: {destination.stat().st_size:,} bytes")

for rid, machine in [("win-x64", 0x8664), ("win-arm64", 0xAA64)]:
    if from_archives:
        destination = artifacts / f"Sentinel-{version}-{rid}.zip"
        with zipfile.ZipFile(destination) as z:
            if z.testzip() is not None or any(not allowed(Path(name)) or Path(name).is_absolute() or ".." in Path(name).parts for name in z.namelist()):
                raise RuntimeError("ZIP integrity/content validation failed")
            for executable in ["Sentinel.exe", "Sentinel.Scanner.exe"]:
                raw = z.read(executable)
                offset = struct.unpack_from("<I", raw, 0x3C)[0]
                if raw[:2] != b"MZ" or raw[offset:offset+4] != b"PE\0\0" or struct.unpack_from("<H", raw, offset+4)[0] != machine:
                    raise RuntimeError(f"Wrong PE architecture for {executable}/{rid}")
            for assembly in ["Sentinel", "Sentinel.Scanner"]:
                runtime = json.loads(z.read(assembly + ".runtimeconfig.json"))["runtimeOptions"]
                if "includedFrameworks" not in runtime:
                    raise RuntimeError("Expected a self-contained runtime")
                if f"{assembly}/{version}" not in json.loads(z.read(assembly + ".deps.json"))["libraries"]:
                    raise RuntimeError("Packaged dependency version mismatch")
            for name in ["LICENSE", "README.md"]:
                if z.read(name) != (root / name).read_bytes():
                    raise RuntimeError(f"Packaged {name} does not match the release source")
        outputs.append(destination)
        print(f"PASS {destination.name}: {destination.stat().st_size:,} bytes (Windows CI archive)")
        continue
    folder = artifacts / "portable" / rid
    for executable in ["Sentinel.exe", "Sentinel.Scanner.exe"]:
        raw = (folder / executable).read_bytes()
        offset = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[:2] != b"MZ" or raw[offset:offset+4] != b"PE\0\0" or struct.unpack_from("<H", raw, offset+4)[0] != machine:
            raise RuntimeError(f"Wrong PE architecture for {executable}/{rid}")
    for assembly in ["Sentinel", "Sentinel.Scanner"]:
        runtime = json.loads((folder / (assembly + ".runtimeconfig.json")).read_text())["runtimeOptions"]
        if "includedFrameworks" not in runtime:
            raise RuntimeError("Expected a self-contained runtime")
        deps = json.loads((folder / (assembly + ".deps.json")).read_text())["libraries"]
        if f"{assembly}/{version}" not in deps:
            raise RuntimeError("Packaged dependency version mismatch")
    for name in ["LICENSE", "README.md"]:
        shutil.copy2(root / name, folder / name)
    shutil.copytree(root / "docs", folder / "docs", dirs_exist_ok=True)
    for path in server_files:
        dest = folder / "server" / path.relative_to(root / "server")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    archive(f"Sentinel-{version}-{rid}.zip", [(p, p.relative_to(folder).as_posix()) for p in folder.rglob("*") if p.is_file()])

source = []
for name in ["README.md", "LICENSE", "Directory.Build.props", ".gitignore", ".gitattributes"]:
    if (root / name).is_file():
        source.append((root / name, "Sentinel/" + name))
for name in ["src", "tests", "docs", "scripts", ".github"]:
    for p in (root / name).rglob("*"):
        relative = p.relative_to(root)
        if p.is_file() and allowed(relative):
            source.append((p, "Sentinel/" + relative.as_posix()))
source.extend((p, "Sentinel/" + p.relative_to(root).as_posix()) for p in server_files)
archive(f"Sentinel-{version}-source.zip", source)
archive(f"Sentinel-{version}-server.zip", [(p, p.relative_to(root).as_posix()) for p in server_files] + [(root / "LICENSE", "LICENSE")])
checksum = artifacts / f"SHA256SUMS-v{version}.txt"
checksum.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in outputs))
print(f"PASS architecture/runtime/version/integrity/content checks; {checksum.name} saved")
