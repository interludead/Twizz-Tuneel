# Twizz Tuneel

Windows x64 client built with Tauri 2 and Rust, with sing-box, Xray-core and Mihomo support.

## Download

Download the Windows installer from [Releases](https://github.com/interludead/Twizz-Tuneel/releases). Version: **1.12.0**.

## Build on Windows

Run `./build-windows.ps1` in PowerShell. The script prepares dependencies, downloads the runtime cores, runs project checks and Rust tests, and builds the application with NSIS and MSI installers.

Build requirements include Node.js, Rust MSVC, Microsoft C++ Build Tools and the Windows SDK. Python is used for static verification.

Installer outputs: `src-tauri/target/release/bundle/nsis/` and `src-tauri/target/release/bundle/msi/`.

## Third-party components

Runtime cores are embedded during compilation and downloaded by the build script from their upstream projects: [sing-box](https://github.com/SagerNet/sing-box), [Xray-core](https://github.com/XTLS/Xray-core), and [Mihomo](https://github.com/MetaCubeX/mihomo). Their respective licenses apply.

Local caches, subscription data, downloaded build tools and build outputs are excluded from this source repository.
