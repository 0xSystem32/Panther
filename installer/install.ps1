# Installateur Panther pour Windows (sans droits administrateur).
#   powershell -ExecutionPolicy Bypass -File installer\install.ps1              installe
#   powershell -ExecutionPolicy Bypass -File installer\install.ps1 -Uninstall   désinstalle (la configuration est conservée)
param([switch]$Uninstall, [string]$Prefix = "$env:LOCALAPPDATA\Panther")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$menu = Join-Path ([Environment]::GetFolderPath("Programs")) "Panther.lnk"

if ($Uninstall) {
    Remove-Item -Recurse -Force $Prefix, $menu -ErrorAction SilentlyContinue
    Write-Host "Panther désinstallé. Vos réglages restent dans %APPDATA%\Panther."
    exit 0
}

$py = $null
foreach ($c in @("py -3.13", "py -3.12", "python")) {
    try {
        $parts = $c.Split(" ")
        & $parts[0] $parts[1..($parts.Length - 1)] -c "import sys; sys.exit(sys.version_info < (3, 12))" 2>$null
        if ($LASTEXITCODE -eq 0) { $py = $parts; break }
    } catch { }
}
if (-not $py) { throw "Python 3.12 ou plus récent est nécessaire (https://www.python.org/downloads/)." }

Write-Host "Installation dans $Prefix…"
& $py[0] $py[1..($py.Length - 1)] -m venv "$Prefix\venv"
& "$Prefix\venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "$Prefix\venv\Scripts\python.exe" -m pip install --quiet $root

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($menu)
$lnk.TargetPath = "$Prefix\venv\Scripts\pythonw.exe"
$lnk.Arguments = "-m panther"
$lnk.Description = "Scanner et cartographie de réseau local"
$lnk.Save()

Write-Host "Terminé : Panther est dans le menu Démarrer."
Write-Host "Note : le scan réseau n'est géré que sous Linux ; sous Windows l'interface et le mode --demo fonctionnent."
