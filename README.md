# Twizz Tuneel

VPN-клиент для Windows x64 с поддержкой sing-box, Xray-core и Mihomo. Интерфейс работает на Tauri 2, а серверная часть приложения написана на Rust.

## Скачать

Установщик Windows x64 доступен на [странице предварительного релиза 1.2.0 RC](https://github.com/interludead/Twizz-Tuneel/releases/tag/v1.2.0-rc). Другие версии доступны в [разделе релизов](https://github.com/interludead/Twizz-Tuneel/releases).

## Сборка на Windows

Запустите `./build-windows.ps1` в PowerShell. Сценарий подготовит зависимости, скачает сетевые ядра, выполнит проверки и соберёт приложение и установщики NSIS и MSI.

Для сборки используются Node.js, Rust с инструментами MSVC, Microsoft C++ Build Tools и Windows SDK. Python нужен для статической проверки проекта.

Установщики будут в папках `src-tauri/target/release/bundle/nsis/` и `src-tauri/target/release/bundle/msi/`. Версия без установки сохраняется в `dist/Twizz-Tuneel-TUN.exe`.

## Сторонние компоненты

Во время сборки в приложение встраиваются [sing-box](https://github.com/SagerNet/sing-box), [Xray-core](https://github.com/XTLS/Xray-core) и [Mihomo](https://github.com/MetaCubeX/mihomo). Для каждого компонента действует лицензия его проекта.
