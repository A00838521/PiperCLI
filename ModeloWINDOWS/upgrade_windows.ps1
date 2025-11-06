# Upgrade Piper CLI (Windows)
# - Actualiza fuentes y wrapper
# - No reinstala modelos; lista los existentes
param(
  [switch]$DryRun
)

if (-not ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))) {
  Write-Error "[ERROR] Solo Windows"; exit 2
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $here '..')).Path
$HOME = $env:USERPROFILE
$BinHome = Join-Path $HOME '.local\bin'
$PiperHome = Join-Path $HOME '.local\share\piper-cli'
$PiperSrc = Join-Path $PiperHome 'src'
$Wrapper = Join-Path $BinHome 'piper.cmd'

Write-Host "`n== Piper Upgrade (Windows) ==`n"
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $PiperSrc | Out-Null }
if (-not $DryRun) { Copy-Item -Recurse -Force -Path (Join-Path $repoRoot 'src\*') -Destination $PiperSrc }

if (-not (Test-Path $Wrapper)) {
  @"@echo off
setlocal
set PY=%PYTHON%
if "%PY%"=="" set PY=python
set PIPER_HOME=%USERPROFILE%\.local\share\piper-cli
set SRC_DIR=%PIPER_HOME%\src
set PYTHONPATH=%SRC_DIR%;%PYTHONPATH%
"%PY%" "%PIPER_HOME%\src\piper_cli.py" %*
endlocal
"@ | Set-Content -LiteralPath $Wrapper -Encoding ASCII
}

# Listar modelos instalados
function Test-Command($n){ $null -ne (Get-Command $n -ErrorAction SilentlyContinue) }
if (Test-Command 'ollama') {
  Write-Host "\nModelos instalados (ollama list):"
  try { ollama list } catch { Write-Warning $_; Write-Host "(Fallback API tags)"; try { Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5 | Select-Object -ExpandProperty Content } catch {} }
} else {
  Write-Host "[INFO] Ollama no está en PATH"
}

Write-Host "\nUpgrade finalizado."