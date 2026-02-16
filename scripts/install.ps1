param(
    [string]$Owner = "nodyhody",
    [string]$Repo = "vaulty",
    [string]$BinName = "vaulty",
    [string]$InstallDir = "$HOME\\bin",
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

function Get-Target {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        "ARM64" { return "aarch64-pc-windows-msvc" }
        default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Resolve-Version {
    if ($Version -ne "latest") {
        return $Version.TrimStart("v")
    }

    $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    if (-not $latest.tag_name) {
        throw "Could not resolve latest version from GitHub releases."
    }
    return $latest.tag_name.TrimStart("v")
}

$target = Get-Target
$resolved = Resolve-Version
$asset = "$BinName-$resolved-$target.zip"
$url = "https://github.com/$Owner/$Repo/releases/download/v$resolved/$asset"

$tmp = Join-Path $env:TEMP "vaulty-install-$resolved"
if (Test-Path $tmp) {
    Remove-Item -Path $tmp -Recurse -Force
}
New-Item -Path $tmp -ItemType Directory | Out-Null

$archive = Join-Path $tmp $asset
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $archive
Expand-Archive -LiteralPath $archive -DestinationPath $tmp -Force

if (-not (Test-Path $InstallDir)) {
    New-Item -Path $InstallDir -ItemType Directory | Out-Null
}

$source = Join-Path $tmp "$BinName.exe"
$dest = Join-Path $InstallDir "$BinName.exe"
Copy-Item -Path $source -Destination $dest -Force

Write-Host "Installed $BinName.exe to $dest"
Write-Host "Add $InstallDir to PATH if needed."
