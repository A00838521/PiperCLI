#requires -version 5.1
<#!
Desinstalador de Piper CLI para Windows (ModeloWINDOWS)
Uso:
  powershell -ExecutionPolicy Bypass -File .\ModeloWINDOWS\uninstall_windows.ps1 [-KeepState]
#>
param(
  [switch]$KeepState
)

if (-not ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))) {
  Write-Error "[ERROR] Este desinstalador es solo para Windows"; exit 2
}

$ErrorActionPreference = 'Stop'
$HOME = $env:USERPROFILE
$BinHome = Join-Path $HOME '.local\\bin'
$Wrapper = Join-Path $BinHome 'piper.cmd'
$PiperHome = Join-Path $HOME '.local\\share\\piper-cli'
$PiperState = Join-Path $HOME '.local\\share\\piper'

Write-Host "`n== Piper Uninstaller (Windows) ==`n"

# Detener ollama si se desea
try {
  & taskkill /F /IM ollama.exe | Out-Null
} catch { }
try {
  & powershell -NoProfile -Command "Get-Process ollama -ErrorAction SilentlyContinue | Stop-Process -Force" | Out-Null
} catch { }

# Quitar wrapper
if (Test-Path $Wrapper) { Remove-Item -Force $Wrapper; Write-Host "- Eliminado wrapper: $Wrapper" } else { Write-Host "- Wrapper no encontrado (ok)" }

# Quitar instalación del CLI
if (Test-Path $PiperHome) { Remove-Item -Recurse -Force $PiperHome; Write-Host "- Eliminado: $PiperHome" } else { Write-Host "- Directorio de instalación no encontrado (ok)" }

# Estado
if ($KeepState) {
  Write-Host "- Conservando estado en $PiperState"
} else {
  if (Test-Path $PiperState) { Remove-Item -Recurse -Force $PiperState; Write-Host "- Eliminado estado: $PiperState" } else { Write-Host "- Estado no encontrado (ok)" }
}

Write-Host "`nDesinstalación completada. Si agregaste %USERPROFILE%\\.local\\bin al PATH, permanece en PATH; puedes retirarlo manualmente en Configuración si lo deseas."
