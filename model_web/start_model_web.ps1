$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    $taskPython = Join-Path (Split-Path -Parent $PSScriptRoot) '.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $taskPython)) {
    $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    $workspaceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $localDeps = Join-Path $workspaceRoot 'work_revision\ml_dependencies'
    if ((Test-Path -LiteralPath $bundledPython) -and (Test-Path -LiteralPath $localDeps)) {
        $taskPython = $bundledPython
        $env:PYTHONPATH = $localDeps
    } else {
        $taskPython = (Get-Command python -ErrorAction Stop).Source
    }
}
& $taskPython -c 'import numpy, pandas, sklearn, joblib'
if ($LASTEXITCODE -ne 0) { throw 'Install requirements.txt in a Python virtual environment first.' }
Write-Host 'Open http://127.0.0.1:8765 in your browser. Press Ctrl+C to stop.'
& $taskPython (Join-Path $PSScriptRoot 'model_web.py')
if ($LASTEXITCODE -ne 0) { throw 'Server stopped with an error. See the message above.' }
