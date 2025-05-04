import hashlib
import json
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

CARGO_TOML_PATH = Path("./Cargo.toml")

SIGNING_KEY_PATH = Path("./saekawa.pfx")
SIGNING_KEY_PASSWORD = os.environ.get("SAEKAWA_SIGNING_KEY_PASSWORD", "saekawa")

COMPILED_OUTPUT = "target/i686-pc-windows-msvc/release/saekawa.dll"

DIST_FOLDER = Path("dist/")
GITHUB_DIST_FOLDER = DIST_FOLDER / "github"
RAINYCOLOR_WATERCOLOR_FOLDER = DIST_FOLDER / "rainycolor-watercolor"


with CARGO_TOML_PATH.open("rb") as f:
    cargo_toml = tomllib.load(f)

if SIGNING_KEY_PATH.exists():
    print("[INFO] Making GitHub release...")

    r = subprocess.run(
        [
            "cargo",
            "build",
            "--target",
            "i686-pc-windows-msvc",
            "--release",
            "--features",
            "autoupdate",
        ],
    )
    r.check_returncode()

    r = subprocess.run(
        [
            "signtool",
            "sign",
            "-f",
            "saekawa.pfx",
            "-p",
            SIGNING_KEY_PASSWORD,
            "-fd",
            "SHA256",
            "-t",
            "http://timestamp.comodoca.com/authenticode",
            "-v",
            COMPILED_OUTPUT,
        ]
    )
    r.check_returncode()

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
    ["cargo", "build", "--target", "i686-pc-windows-msvc", "--release"],
)
r.check_returncode()

r = subprocess.run(
    [
        "signtool",
        "sign",
        "-f",
        "saekawa.pfx",
        "-p",
        SIGNING_KEY_PASSWORD,
        "-fd",
        "SHA256",
        "-t",
        "http://timestamp.comodoca.com/authenticode",
        "-v",
        COMPILED_OUTPUT,
    ]
)
r.check_returncode()

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

rainycolor_watercolor_readme = """<h1 align="center">saekawa</h1>

<p align="center">インパアフェクシオン・ホワイトガアル</p>

CHUNITHM hook to submit your scores to Tachi every credit.

### Features
- Submit scores to Tachi after each credit.
- Submit dan and emblem classes to Tachi.

### Usage
Download a config file pre-filled with your Tachi API key [here](https://kamai.tachi.ac/client-file-flow/CXSaekawa)
and point STARTLINER to your config file.

Scores are sent after every credit. If score submission is taking a long time, please don't close the game just yet.
You can monitor that the hook is working through the console, or through the `saekawa.log` log file.

### Credits
- Adam Thibert ([adamaq01](https://github.com/adamaq01)). A lot of the code was copied from
[Mikado](https://github.com/adamaq01/Mikado), a similar hook for SDVX.

### License
0BSD
"""
with (RAINYCOLOR_WATERCOLOR_FOLDER / "README.md").open("w", encoding="utf-8") as f:
    _ = f.write(rainycolor_watercolor_readme)

_ = shutil.copy2("res/icon.png", RAINYCOLOR_WATERCOLOR_FOLDER / "icon.png")
_ = shutil.copy2(COMPILED_OUTPUT, RAINYCOLOR_WATERCOLOR_FOLDER / "saekawa.dll")
