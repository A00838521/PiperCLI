#requires -version 5.1
<#!
Instalador de Piper CLI para Windows (ModeloWINDOWS)
- Copia Piper a %USERPROFILE%\.local\share\piper-cli\src y crea wrapper en %USERPROFILE%\.local\bin\piper.cmd
- Intenta instalar Ollama con winget si está disponible y lo arranca en background
- Aplica configuración inicial y predescarga modelos indicados en ENSURE_MODELS

Uso:
  powershell -ExecutionPolicy Bypass -File .\ModeloWINDOWS\install_windows.ps1
#>

param(
  [string]$EnsureModels = $env:ENSURE_MODELS,
  [string]$Model
)

if (-not ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))) {
  Write-Error "[ERROR] Este instalador es solo para Windows"; exit 2
}

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $here '..')).Path

# Rutas destino (alineadas con macOS/Linux para compatibilidad de logs/estado)
$HOME = $env:USERPROFILE
$BinHome = Join-Path $HOME '.local\\bin'
$PiperHome = Join-Path $HOME '.local\\share\\piper-cli'
$PiperSrc = Join-Path $PiperHome 'src'
$PiperState = Join-Path $HOME '.local\\share\\piper'
$Wrapper = Join-Path $BinHome 'piper.cmd'

Write-Host "`n== Piper Installer (Windows) ==`n"
Write-Host "Destino: $PiperHome"
Write-Host "Wrapper: $Wrapper"

# Crear carpetas
New-Item -ItemType Directory -Force -Path $PiperSrc | Out-Null
New-Item -ItemType Directory -Force -Path $BinHome | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PiperHome 'logs') | Out-Null
New-Item -ItemType Directory -Force -Path $PiperState | Out-Null

# Copiar fuentes del CLI
Copy-Item -Recurse -Force -Path (Join-Path $repoRoot 'src\*') -Destination $PiperSrc

# Wrapper piper.cmd
@"
@echo off
setlocal
set PY=%PYTHON%
if "%PY%"=="" set PY=python
set PIPER_HOME=%USERPROFILE%\.local\share\piper-cli
set SRC_DIR=%PIPER_HOME%\src
set PYTHONPATH=%SRC_DIR%;%PYTHONPATH%
"%PY%" "%PIPER_HOME%\src\piper_cli.py" %*
endlocal
"@ | Set-Content -LiteralPath $Wrapper -Encoding ASCII

# Si se indicó -Model, usarlo como modelo por defecto y para pulls
if ($Model) {
  try {
    Add-Content -LiteralPath $Wrapper -Value "`nset PIPER_OLLAMA_MODEL=$Model" -Encoding ASCII
  } catch {}
  $EnsureModels = $Model
}

# Asegurar Bin en PATH
if (-not ($env:Path -split ';' | Where-Object { $_ -eq $BinHome })) {
  try {
    $newPath = "$env:Path;$BinHome"
    setx PATH $newPath | Out-Null
    Write-Host "[INFO] Agregado $BinHome a PATH del usuario (abre una nueva consola para que surta efecto)"
  } catch {
    Write-Warning "No se pudo persistir PATH, agrega $BinHome manualmente a tu PATH de usuario"
  }
}

# Dependencias opcionales
function Test-Command($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

# Instalar Ollama si no existe
if (-not (Test-Command 'ollama')) {
  if (Test-Command 'winget') {
    Write-Host "[INFO] Instalando Ollama via winget..."
    try {
      winget install -e --id Ollama.Ollama --source winget --accept-package-agreements --accept-source-agreements -h | Out-Null
    } catch {
      Write-Warning "winget falló al instalar Ollama: $_"
    }
  } elseif (Test-Command 'choco') {
    Write-Host "[INFO] Instalando Ollama via Chocolatey..."
    try { choco install -y ollama | Out-Null } catch { Write-Warning $_ }
  } else {
    Write-Warning "No se encontró winget ni choco. Instala Ollama manualmente desde https://ollama.com/download"
  }
}

# Iniciar Ollama en background si es posible
if (Test-Command 'ollama') {
  try {
    Start-Process -WindowStyle Hidden -FilePath 'ollama' -ArgumentList 'serve' | Out-Null
    Write-Host "[INFO] ollama serve lanzado en background"
  } catch {
    Write-Warning "No se pudo iniciar ollama serve: $_"
  }
}

# Copiar config por defecto
$defaultCfg = Join-Path $repoRoot 'state\config.json'
if (Test-Path $defaultCfg) {
  Copy-Item -Force -Path $defaultCfg -Destination (Join-Path $PiperState 'config.json')
}

# Aplicar defaults (idempotente)
try {
  & $Wrapper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python | Out-Null
} catch { }

# Asegurar modelos
if (-not $EnsureModels) { $EnsureModels = 'mistral:7b-instruct,phi3:mini' }
if (Test-Command 'ollama') {
  $models = $EnsureModels.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  foreach ($m in $models) {
    Write-Host "[INFO] Asegurando modelo: $m"
    try { & ollama pull $m | Out-Null } catch { Write-Warning $_ }
  }
}

Write-Host "`n== Comprobación =="
if (Test-Path $Wrapper) { Write-Host "- Piper instalado en: $Wrapper" } else { Write-Warning "Piper no se instaló correctamente" }
try {
  $resp = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5
  if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) { Write-Host "- Ollama responde en 127.0.0.1:11434" }
} catch { Write-Warning "No se pudo verificar Ollama vía HTTP (puede ser temporal)" }

Write-Host "`nInstalación finalizada. Abre una nueva terminal para que PATH se refresque."
