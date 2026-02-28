import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import tomllib

CARGO_TOML_PATH = Path("./Cargo.toml")
CARGO_BUILD_COMMAND = (
    ["cargo", "build"] if os.name == "nt" else ["cargo", "xwin", "build"]
)

SIGNING_KEY_PATH = Path("./saekawa.pfx")
SIGNING_KEY_PASSWORD = os.environ.get("SAEKAWA_SIGNING_KEY_PASSWORD", "saekawa")

COMPILED_OUTPUT = Path("target/i686-pc-windows-msvc/release/saekawa.dll")
COMPILED_SIGNED_OUTPUT = COMPILED_OUTPUT.with_suffix(".signed" + COMPILED_OUTPUT.suffix)

DIST_FOLDER = Path("dist/")
GITHUB_DIST_FOLDER = DIST_FOLDER / "github"
RAINYCOLOR_WATERCOLOR_FOLDER = DIST_FOLDER / "rainycolor-watercolor"


def sign_executable(key: Path, password: str, file: Path):
    if os.name == "nt":
        r = subprocess.run(
            [
                "signtool",
                "sign",
                "-f",
                str(key),
                "-p",
                password,
                "-fd",
                "SHA256",
                "-t",
                "http://timestamp.comodoca.com/authenticode",
                "-v",
                str(file),
            ]
        )
        r.check_returncode()
    else:
        signed_file = file.with_suffix(".signed" + file.suffix)
        r = subprocess.run(
            [
                "osslsigncode",
                "sign",
                "-pkcs12",
                str(key),
                "-pass",
                password,
                "-h",
                "sha256",
                "-t",
                "http://timestamp.comodoca.com/authenticode",
                "-in",
                str(file),
                "-out",
                str(signed_file),
            ]
        )
        r.check_returncode()
        signed_file.rename(file)


with CARGO_TOML_PATH.open("rb") as f:
    cargo_toml = tomllib.load(f)

if SIGNING_KEY_PATH.exists():
    print("[INFO] Making GitHub release...")

    r = subprocess.run(
        [
            *CARGO_BUILD_COMMAND,
            "--target",
            "i686-pc-windows-msvc",
            "--release",
            "--features",
            "autoupdate",
        ],
    )
    r.check_returncode()

    sign_executable(SIGNING_KEY_PATH, SIGNING_KEY_PASSWORD, COMPILED_OUTPUT)

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

    with open(COMPILED_OUTPUT, "rb") as f:
        s = hashlib.sha256()

        while True:
            d = f.read(1_048_576)

            if not d:
                break

            s.update(d)

        sha256 = s.hexdigest()

    shutil.rmtree(GITHUB_DIST_FOLDER, ignore_errors=True)
    GITHUB_DIST_FOLDER.mkdir(parents=True, exist_ok=True)

    update_manifest = {
        "version": cargo_toml["package"]["version"],
        "commit": commit,
        "sha256": sha256,
    }

    with (GITHUB_DIST_FOLDER / "update.json").open("w", encoding="utf-8") as f:
        json.dump(update_manifest, f, ensure_ascii=False, indent=4)

    _ = shutil.copy2(COMPILED_OUTPUT, GITHUB_DIST_FOLDER / "saekawa.dll")
else:
    print("[WARN] Cannot make GitHub release. Signing key is missing.")

print("[INFO] Making Rainycolor Watercolor release...")
r = subprocess.run(
    [*CARGO_BUILD_COMMAND, "--target", "i686-pc-windows-msvc", "--release"],
)
r.check_returncode()

if SIGNING_KEY_PATH.exists():
    sign_executable(SIGNING_KEY_PATH, SIGNING_KEY_PASSWORD, COMPILED_OUTPUT)

shutil.rmtree(RAINYCOLOR_WATERCOLOR_FOLDER, ignore_errors=True)
RAINYCOLOR_WATERCOLOR_FOLDER.mkdir(parents=True, exist_ok=True)

rainycolor_watercolor_manifest = {
    "name": "saekawa",
    "version_number": cargo_toml["package"]["version"],
    "website_url": "https://github.com/beer-psi/saekawa",
    "description": "Score uploader for Kamaitachi",
    "dependencies": [],
    "installers": [{"identifier": "native_mod", "dll_game": "saekawa.dll"}],
}
with (RAINYCOLOR_WATERCOLOR_FOLDER / "manifest.json").open("w", encoding="utf-8") as f:
    json.dump(rainycolor_watercolor_manifest, f, ensure_ascii=False, indent=4)

_ = shutil.copy2("README.rainycolor.md", RAINYCOLOR_WATERCOLOR_FOLDER / "README.md")
_ = shutil.copy2("res/icon.png", RAINYCOLOR_WATERCOLOR_FOLDER / "icon.png")
_ = shutil.copy2(COMPILED_OUTPUT, RAINYCOLOR_WATERCOLOR_FOLDER / "saekawa.dll")
