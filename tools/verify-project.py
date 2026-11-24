#!/usr/bin/env python3
"""Static verification for the LZT Tunnel multi-core client.

Checks that can be performed without a Windows toolchain:
  1. every invoke('cmd') used by the UI is registered in the Tauri handler
  2. every `mod x;` in main.rs has a matching source file
  3. braces/parens/brackets are balanced in every Rust file
  4. the connect request keys sent by the UI exist in ConnectRequest
  5. preflight strings asserted by build-windows.ps1 really exist
  6. no demo/stub markers leaked into the UI
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src-tauri" / "src"
UI = ROOT / "ui" / "index.html"

errors: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        errors.append(message)


main_rs = (SRC / "main.rs").read_text(encoding="utf-8")
ui = UI.read_text(encoding="utf-8")

# 1. Tauri commands
handler = re.search(r"generate_handler!\[(.*?)\]", main_rs, re.S)
check(handler is not None, "generate_handler! block not found in main.rs")
registered = set()
if handler:
    registered = {name.strip() for name in handler.group(1).split(",") if name.strip()}
    for name in sorted(registered):
        check(
            re.search(r"fn\s+" + re.escape(name) + r"\s*\(", main_rs) is not None,
            f"command {name} is registered but has no fn in main.rs",
        )

used = set(re.findall(r"invoke\('([a-z_]+)'", ui))
for name in sorted(used):
    check(name in registered, f"UI calls invoke('{name}') which is not registered")

# 2. modules
for module in re.findall(r"^mod\s+([a-z_]+);", main_rs, re.M):
    check((SRC / f"{module}.rs").exists(), f"mod {module}; has no {module}.rs")

# 3. delimiter balance
def strip_literals(text: str) -> str:
    """Drop char literals, string literals and comments before counting."""
    text = re.sub(r"r?\"(\\.|[^\"\\])*\"", '""', text, flags=re.S)
    text = re.sub(r"'(\\.|[^'\\])'", "' '", text)
    text = re.sub(r"//[^\n]*", "", text)
    return text


for rust_file in sorted(SRC.glob("*.rs")):
    text = strip_literals(rust_file.read_text(encoding="utf-8"))
    for opening, closing in (("{", "}"), ("(", ")"), ("[", "]")):
        check(
            text.count(opening) == text.count(closing),
            f"{rust_file.name}: unbalanced {opening}{closing} "
            f"({text.count(opening)} vs {text.count(closing)})",
        )

# 4. connect request payload
model = (SRC / "model.rs").read_text(encoding="utf-8")
connect_struct = re.search(r"pub struct ConnectRequest \{(.*?)\n\}", model, re.S)
check(connect_struct is not None, "ConnectRequest struct not found")
if connect_struct:
    fields = set(re.findall(r"pub ([a-z_0-9]+):", connect_struct.group(1)))
    payload = re.search(r"invoke\('connect',\{request:\{(.*?)\}\}\)", ui, re.S)
    check(payload is not None, "connect payload not found in the UI")
    if payload:
        body = payload.group(1)
        depth = 0
        keys = []
        for match in re.finditer(r"[\{\[\(\}\]\)]|([a-z_0-9]+):", body):
            token = match.group(0)
            if token in "{[(":
                depth += 1
            elif token in "}])":
                depth -= 1
            elif depth == 0 and match.group(1):
                keys.append(match.group(1))
        for key in keys:
            check(key in fields, f"UI sends connect.{key} but ConnectRequest has no such field")
        check("core_preference" in keys, "UI does not send core_preference on connect")

# 5. build script preflight assertions really match
ps1 = (ROOT / "build-windows.ps1").read_text(encoding="utf-8")
block = re.search(r"\$requiredChecks = @\((.*?)\n\)", ps1, re.S)
check(block is not None, "$requiredChecks block not found in build-windows.ps1")
if block:
    for rel, pattern in re.findall(r"Path = \"(.*?)\";\s*Pattern = ['\"](.*?)['\"] \}", block.group(1)):
        target = ROOT / rel.replace("\\", "/")
        check(target.exists(), f"preflight target missing: {rel}")
        if target.exists():
            body = target.read_text(encoding="utf-8")
            check(
                re.search(pattern, body) is not None,
                f"preflight pattern not found in {rel}: {pattern}",
            )

# 6. no stub markers
for marker in ("Math.random", "example.net", "LZT Premium", "Backup VPN", "demoSubscriptions", "const samples="):
    check(marker not in ui, f"demo/stub marker found in UI: {marker}")

# 7. core wiring sanity
for needle, where, text in (
    ("plan_cores", "main.rs", main_rs),
    ("start_upstream_core", "main.rs", main_rs),
    ("BRIDGE_PORT", "cores.rs", (SRC / "cores.rs").read_text(encoding="utf-8")),
    ("corePreference", "ui/index.html", ui),
    ("refreshCorePlans", "ui/index.html", ui),
):
    check(needle in text, f"{needle} missing from {where}")

for core in ("sing-box.exe", "xray.exe", "mihomo.exe"):
    check(core in main_rs, f"{core} is not embedded in main.rs")
    check(core in ps1, f"{core} is not fetched by build-windows.ps1")

print(f"verify-project: {checks} checks, {len(errors)} problem(s)")
for error in errors:
    print(f"  FAIL {error}")
sys.exit(1 if errors else 0)
