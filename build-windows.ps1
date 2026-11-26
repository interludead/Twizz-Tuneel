$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$tools = Join-Path $root ".tools"
New-Item -ItemType Directory -Path $tools -Force | Out-Null

Write-Host "LZT Tunnel Windows build"

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) {
    $env:Path = $cargoBin + ";" + $env:Path
}

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargoCommand) {
    Write-Host "[1/5] Installing Rust..."
    $rustup = Join-Path $tools "rustup-init.exe"
    Invoke-WebRequest -UseBasicParsing -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustup
    $rustProcess = Start-Process -FilePath $rustup -ArgumentList "-y --default-toolchain stable --default-host x86_64-pc-windows-msvc" -Wait -PassThru
    if ($rustProcess.ExitCode -ne 0) {
        throw "Rust installation failed."
    }
    $env:Path = $cargoBin + ";" + $env:Path
} else {
    Write-Host "[1/5] Rust found."
}

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $nodeCommand) {
    $oldNode = Get-ChildItem -Path $tools -Directory -Filter "node-*-win-x64" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $oldNode) {
        $env:Path = $oldNode.FullName + ";" + $env:Path
    }
}

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $nodeCommand) {
    Write-Host "[2/5] Downloading portable Node.js LTS..."
    $nodeIndex = Invoke-RestMethod -Uri "https://nodejs.org/dist/index.json"
    $nodeRelease = $nodeIndex | Where-Object { $null -ne $_.lts -and $_.lts -ne $false } | Select-Object -First 1
    if ($null -eq $nodeRelease) {
        throw "Cannot determine Node.js LTS version."
    }
    $nodeVersion = $nodeRelease.version
    $nodeZip = Join-Path $tools ("node-" + $nodeVersion + ".zip")
    $nodeFolder = Join-Path $tools ("node-" + $nodeVersion + "-win-x64")
    $nodeUrl = "https://nodejs.org/dist/" + $nodeVersion + "/node-" + $nodeVersion + "-win-x64.zip"
    Invoke-WebRequest -UseBasicParsing -Uri $nodeUrl -OutFile $nodeZip
    Expand-Archive -Path $nodeZip -DestinationPath $tools -Force
    $env:Path = $nodeFolder + ";" + $env:Path
} else {
    Write-Host "[2/5] Node.js found."
}

if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is not available. Restart PowerShell and run this script again."
}
Write-Host "Checking the installed Rust toolchain..."
& cargo --version
if ($LASTEXITCODE -ne 0) { throw "cargo cannot start." }
& rustc --version
if ($LASTEXITCODE -ne 0) { throw "rustc cannot start." }
$installedTargets = @(& rustup target list --installed 2>$null)
if ($installedTargets -notcontains "x86_64-pc-windows-msvc") {
    Write-Host "Installing the missing Windows Rust target..."
    & rustup target add x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "Cannot install the Windows Rust target. Check the connection and retry." }
} else {
    Write-Host "Stable MSVC toolchain is already ready. Skipping network update."
}
if ($null -eq (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm is not available."
}

$cppFound = $false
if (Test-Path "C:\BuildTools\VC\Tools\MSVC") {
    $cppFound = $true
}
$programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($null -ne $vsPath -and $vsPath.Length -gt 0) {
        $cppFound = $true
    }
}

if ($cppFound -eq $false) {
    Write-Host "[3/5] Installing Microsoft C++ Build Tools and Windows SDK. This can take 10-30 minutes..."
    $vsInstaller = Join-Path $tools "vs_BuildTools.exe"
    Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile $vsInstaller
    $vsArgs = "--quiet --wait --norestart --nocache --installPath C:\BuildTools --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    $vsProcess = Start-Process -FilePath $vsInstaller -ArgumentList $vsArgs -Wait -PassThru
    if ($vsProcess.ExitCode -eq 3010) {
        Write-Host "Restart Windows, then run this script again."
        exit 3010
    }
    if ($vsProcess.ExitCode -ne 0) {
        throw ("Build Tools installation failed with code " + $vsProcess.ExitCode)
    }
} else {
    Write-Host "[3/5] Microsoft C++ Build Tools found."
}

Write-Host "[preflight] Checking required runtime features and forbidden demo code..."
$requiredChecks = @(
    @{ Path = "src-tauri\Cargo.toml"; Pattern = 'features\s*=\s*\[\s*"rustls-tls"\s*,\s*"json"\s*\]' },
    @{ Path = "src-tauri\Cargo.toml"; Pattern = 'percent-encoding\s*=\s*"2"' },
    @{ Path = "src-tauri\src\main.rs"; Pattern = 'header\("x-hwid"' },
    @{ Path = "src-tauri\src\main.rs"; Pattern = 'fn start_upstream_core' },
    @{ Path = "src-tauri\src\config.rs"; Pattern = '"trojan" =>' },
    @{ Path = "src-tauri\src\cores.rs"; Pattern = 'pub fn plan' },
    @{ Path = "src-tauri\src\xray_config.rs"; Pattern = 'pub fn build' },
    @{ Path = "src-tauri\src\mihomo_config.rs"; Pattern = 'pub fn build' },
    @{ Path = "ui\index.html"; Pattern = "invoke\('core_status'\)" },
    @{ Path = "ui\index.html"; Pattern = "invoke\('plan_cores'" },
    @{ Path = "ui\index.html"; Pattern = 'id="corePreference"' }
)
foreach ($check in $requiredChecks) {
    $target = Join-Path $root $check.Path
    if ((Select-String -Path $target -Pattern $check.Pattern -Quiet) -eq $false) {
        throw ("Regression check failed: " + $check.Path + " / " + $check.Pattern)
    }
}
$uiSource = Get-Content (Join-Path $root "ui\index.html") -Raw
$forbidden = @('Math.random','example.net','LZT Premium','Backup VPN','demoSubscriptions','const samples=')
foreach ($item in $forbidden) {
    if ($uiSource.Contains($item)) { throw ("Demo/stub code detected: " + $item) }
}
Write-Host "Preflight checks passed."

$binDir = Join-Path $root "src-tauri\bin"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

$script:BuilderAgent = "LZT-Tunnel-Builder"
$script:GitHubHeaders = @{ "User-Agent" = $script:BuilderAgent; "Accept" = "application/vnd.github+json" }
$script:CurlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue

function Invoke-NativeSafe { param([string]$FilePath,[string[]]$Arguments) $old=$ErrorActionPreference;try{$ErrorActionPreference="Continue";$output=@(& $FilePath @Arguments 2>&1);[pscustomobject]@{ExitCode=$LASTEXITCODE;Output=$output}}catch{[pscustomobject]@{ExitCode=-1;Output=@($_.Exception.Message)}}finally{$ErrorActionPreference=$old} }

function Get-RemoteText {
    param([string]$Uri)

    # curl.exe uses Schannel differently than .NET and usually survives the
    # "connection closed" TLS failures that break Invoke-RestMethod.
    if ($null -ne $script:CurlCommand) {
        $cr=Invoke-NativeSafe $script:CurlCommand.Source @("-sSL","--fail","--retry","1","--connect-timeout","10","--max-time","30","--http1.1","--tlsv1.2","--ssl-no-revoke","-A",$script:BuilderAgent,"-H","Accept: application/vnd.github+json",$Uri);$lines=$cr.Output
        if ($cr.ExitCode -eq 0 -and $null -ne $lines) {
            $text = ($lines -join "`n")
            if ($text.Trim().Length -gt 0) { return $text }
        }
    }

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $script:GitHubHeaders -ErrorAction Stop
        return [string]$response.Content
    } catch {
        Write-Warning ("Metadata request failed for " + $Uri + ": " + $_.Exception.Message)
    }
    return $null
}

function Get-LatestRelease {
    param([string]$Repo)

    $json = Get-RemoteText ("https://api.github.com/repos/" + $Repo + "/releases/latest")
    if ($null -ne $json) {
        try {
            $release = $json | ConvertFrom-Json
            if ($null -ne $release.tag_name) { return $release }
        } catch {
            Write-Warning ("Cannot parse the GitHub release JSON for " + $Repo + ".")
        }
    }

    # Fallback 1: the releases/latest redirect exposes the tag without the API.
    if ($null -ne $script:CurlCommand) {
        $hr=Invoke-NativeSafe $script:CurlCommand.Source @("-sSIL","--connect-timeout","15","--max-time","60","--http1.1","--tlsv1.2","--ssl-no-revoke","-A",$script:BuilderAgent,("https://github.com/"+$Repo+"/releases/latest"));$head=$hr.Output
        if ($hr.ExitCode -eq 0 -and $null -ne $head) {
            foreach ($line in $head) {
                if ($line -match '^\s*[Ll]ocation:\s*(\S+)' -and $matches[1] -match '/tag/([^/\s]+)$') {
                    return [pscustomobject]@{ tag_name = $matches[1]; assets = @() }
                }
            }
        }
    }

    # Fallback 2: the Atom feed also contains the newest tag.
    $feed = Get-RemoteText ("https://github.com/" + $Repo + "/releases.atom")
    if ($null -ne $feed -and $feed -match '/releases/tag/([^"<>\s]+)') {
        return [pscustomobject]@{ tag_name = $matches[1]; assets = @() }
    }

    Write-Warning ("Cannot read release metadata for " + $Repo + ".")
    return $null
}

function Save-RemoteFile {
    param([string]$Uri, [string]$OutFile, [int]$MinBytes)

    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue

    # Method 1: curl with Schannel workarounds.
    if ($null -ne $script:CurlCommand) {
        $cr=Invoke-NativeSafe $script:CurlCommand.Source @("-L","--fail","--retry","5","--retry-all-errors","--connect-timeout","30","--http1.1","--tlsv1.2","--ssl-no-revoke","-A",$script:BuilderAgent,"-o",$OutFile,$Uri)
        if ($cr.ExitCode -eq 0 -and (Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt $MinBytes) { return $true }
    }

    # Method 2: Windows PowerShell web stack.
    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $script:GitHubHeaders -OutFile $OutFile -ErrorAction Stop
        if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt $MinBytes) { return $true }
    } catch { Write-Warning ("Invoke-WebRequest failed: " + $_.Exception.Message) }

    # Method 3: Background Intelligent Transfer Service.
    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $Uri -Destination $OutFile -ErrorAction Stop
        if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt $MinBytes) { return $true }
    } catch { Write-Warning ("BITS failed: " + $_.Exception.Message) }

    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    return $false
}

function Expand-CoreArchive {
    param([string]$Archive, [string]$Folder)

    if (Test-Path $Folder) { Remove-Item $Folder -Recurse -Force }
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    try {
        Expand-Archive -Path $Archive -DestinationPath $Folder -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Warning ("Expand-Archive failed: " + $_.Exception.Message)
    }
    if ($null -ne (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        & tar.exe -xf $Archive -C $Folder
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

function Find-CoreExe {
    param([string]$Folder, [string]$ExeName, [string]$ExePattern)

    if ((Test-Path $Folder) -eq $false) { return $null }
    $found = Get-ChildItem -Path $Folder -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $found) { return $found }

    # Release archives often rename the binary: MetaCubeX/mihomo ships
    # mihomo-windows-amd64-v1.19.x.exe instead of a plain mihomo.exe.
    if ($null -ne $ExePattern -and $ExePattern.Length -gt 0) {
        $found = Get-ChildItem -Path $Folder -Recurse -File -Filter $ExePattern -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
        if ($null -ne $found) { return $found }
    }

    return Get-ChildItem -Path $Folder -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
}

function Get-CoreBinary {
    param(
        [string]$ExeName,
        [string]$Repo,
        [string]$AssetPattern,
        [string]$FallbackAsset,
        [string]$LocalZipPattern,
        [string]$ExePattern,
        [int]$MinBytes
    )
    $targetExe = Join-Path $binDir $ExeName
    $workFolder = Join-Path $tools ([IO.Path]::GetFileNameWithoutExtension($ExeName))

    # Offline/manual sources are preferred. Put the .exe or the official
    # Windows x64 ZIP next to this script and run the builder again.
    $localExeCandidates = @((Join-Path $root $ExeName), (Join-Path $tools $ExeName))
    foreach ($candidate in $localExeCandidates) {
        if ((Test-Path $targetExe) -eq $false -and (Test-Path $candidate)) {
            Copy-Item $candidate $targetExe -Force
        }
    }

    if ((Test-Path $targetExe) -eq $false) {
        $manualZip = Get-ChildItem -Path $root -Filter $LocalZipPattern -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $manualZip) {
            $manualZip = Get-ChildItem -Path $tools -Filter $LocalZipPattern -File -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($null -ne $manualZip) {
            Write-Host ("[4/5] Using the local archive " + $manualZip.Name + "...")
            if (Expand-CoreArchive $manualZip.FullName $workFolder) {
                $manualExe = Find-CoreExe $workFolder $ExeName $ExePattern
                if ($null -ne $manualExe) { Copy-Item $manualExe.FullName $targetExe -Force }
            }
        }
    }

    if ((Test-Path $targetExe) -eq $false) {
        Write-Host ("[4/5] Downloading " + $ExeName + " from " + $Repo + "...")
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $downloadUrls = @()
        $release = Get-LatestRelease $Repo
        if ($null -ne $release) {
            $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
            if ($null -ne $asset) { $downloadUrls += [string]$asset.browser_download_url }
            if ($FallbackAsset.Length -gt 0 -and $null -ne $release.tag_name) {
                $tag = [string]$release.tag_name
                $version = $tag.TrimStart("v")
                $assetName = $FallbackAsset.Replace("{tag}", $tag).Replace("{version}", $version)
                $downloadUrls += ("https://github.com/" + $Repo + "/releases/download/" + $tag + "/" + $assetName)
            }
        }
        if ($FallbackAsset.Length -gt 0 -and $FallbackAsset.Contains("{") -eq $false) {
            $downloadUrls += ("https://github.com/" + $Repo + "/releases/latest/download/" + $FallbackAsset)
        }
        $downloadUrls = @($downloadUrls | Select-Object -Unique)
        if ($downloadUrls.Count -eq 0) {
            Write-Host ("Open https://github.com/" + $Repo + "/releases/latest manually, download the Windows x64 archive,")
            Write-Host ("place it next to build-windows.ps1 and run the script again.")
            throw ("Cannot resolve a download URL for " + $ExeName + " (" + $Repo + ").")
        }

        $archive = Join-Path $tools ($ExeName + ".zip")
        $downloaded = $false
        foreach ($url in $downloadUrls) {
            Write-Host ("[4/5] Source: " + $url)
            if (Save-RemoteFile $url $archive $MinBytes) { $downloaded = $true; break }
        }

        if ($downloaded -eq $false) {
            Write-Host "Automatic download is blocked by Windows/network TLS." -ForegroundColor Yellow
            foreach ($url in $downloadUrls) { Write-Host ("Download in a browser: " + $url) }
            Write-Host "Place the archive next to build-windows.ps1 and run the script again."
            throw ($ExeName + " download failed with every method.")
        }

        if ((Expand-CoreArchive $archive $workFolder) -eq $false) {
            throw ("Cannot unpack the downloaded archive for " + $ExeName + ".")
        }
        $downloadedExe = Find-CoreExe $workFolder $ExeName $ExePattern
        if ($null -eq $downloadedExe) {
            $listing = ((Get-ChildItem -Path $workFolder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ", ")
            throw ($ExeName + " is missing from the downloaded archive. Archive contents: " + $listing)
        }
        Copy-Item $downloadedExe.FullName $targetExe -Force
    }

    if ((Test-Path $targetExe) -eq $false -or (Get-Item $targetExe).Length -lt $MinBytes) {
        throw ($ExeName + " is missing, empty, or was removed by Windows Security.")
    }
    Write-Host ("[4/5] ready: " + $targetExe)
}

# sing-box is the always-on frontend (TUN/mixed inbound, DNS, routing).
Get-CoreBinary -ExeName "sing-box.exe" -Repo "SagerNet/sing-box" -AssetPattern "windows-amd64[.]zip$" -FallbackAsset "sing-box-{version}-windows-amd64.zip" -LocalZipPattern "sing-box*windows-amd64*.zip" -ExePattern "sing-box*.exe" -MinBytes 1000000
# Xray-core handles XHTTP, mKCP and other Xray-only transports.
Get-CoreBinary -ExeName "xray.exe" -Repo "XTLS/Xray-core" -AssetPattern "^Xray-windows-64[.]zip$" -FallbackAsset "Xray-windows-64.zip" -LocalZipPattern "Xray-windows-64*.zip" -ExePattern "xray*.exe" -MinBytes 1000000
# Mihomo (Clash.Meta) covers Clash-family protocol support. Its archive ships a
# versioned exe name, so the binary is renamed to mihomo.exe after extraction.
Get-CoreBinary -ExeName "mihomo.exe" -Repo "MetaCubeX/mihomo" -AssetPattern "^mihomo-windows-amd64-v[0-9][0-9.]*[.]zip$" -FallbackAsset "mihomo-windows-amd64-{tag}.zip" -LocalZipPattern "mihomo-windows-amd64*.zip" -ExePattern "mihomo*.exe" -MinBytes 1000000

$upxPath=@((Get-Command upx.exe -ErrorAction SilentlyContinue).Source,(Join-Path $root "upx.exe"),(Join-Path $tools "upx.exe"),"C:\Tools\upx\upx.exe",(Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\upx.exe"))|Where-Object{$_ -and (Test-Path $_)}|Select-Object -First 1
if($upxPath){foreach($name in @("sing-box.exe","xray.exe","mihomo.exe")){$file=Join-Path $binDir $name;if((Invoke-NativeSafe $upxPath @("-t",$file)).ExitCode -ne 0){$pack=Invoke-NativeSafe $upxPath @("--best","--lzma","--force-overwrite",$file);if($pack.ExitCode -ne 0){Write-Warning "UPX skipped $name"}}}}else{Write-Warning "UPX not found"}

Write-Host "[verify] Running the static project verifier..."
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) { $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue }
if ($null -ne $pythonCommand) {
    & $pythonCommand.Source (Join-Path $root "tools\verify-project.py")
    if ($LASTEXITCODE -ne 0) { throw "Project verification failed." }
} else {
    Write-Warning "Python was not found, skipping tools\verify-project.py."
}

Write-Host "[test] Running Rust unit tests..."
& cargo test --manifest-path (Join-Path $root "src-tauri\Cargo.toml")
if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }

Write-Host "[5/5] Installing dependencies and building installers..."
& npm install
if ($LASTEXITCODE -ne 0) {
    throw "npm install failed."
}
& npm run build
if ($LASTEXITCODE -ne 0) {
    throw "Tauri build failed."
}

$releaseExe = Join-Path $root "src-tauri\target\release\lzt-tunnel.exe"
if ((Test-Path $releaseExe) -eq $false) { throw "The release executable was not created." }
$outDir = Join-Path $root "dist"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$finalExe = Join-Path $outDir "Twizz-Tuneel-TUN.exe"
Copy-Item -Path $releaseExe -Destination $finalExe -Force
Write-Host "Build completed. Single portable executable:"
Write-Host $finalExe
