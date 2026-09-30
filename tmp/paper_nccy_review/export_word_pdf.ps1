param([string[]]$Paths,[string]$OutputRoot)
$ErrorActionPreference = 'Stop'
$wordApp = New-Object -ComObject Word.Application
$wordApp.Visible = $false
$wordApp.DisplayAlerts = 0
try {
    foreach ($sourcePath in $Paths) {
        $resolvedPath = (Resolve-Path -LiteralPath $sourcePath).Path
        $stem = [IO.Path]::GetFileNameWithoutExtension($resolvedPath)
        $renderDir = Join-Path $OutputRoot $stem
        New-Item -ItemType Directory -Path $renderDir -Force | Out-Null
        $pdfOutput = [IO.Path]::GetFullPath((Join-Path $renderDir "$stem.pdf"))
        $wordDoc = $null
        try {
            $wordDoc = $wordApp.Documents.Open($resolvedPath,$false,$true,$false)
            $wordDoc.Repaginate()
            $pages = $wordDoc.ComputeStatistics(2)
            $wordDoc.ExportAsFixedFormat($pdfOutput,17)
            Write-Output "$stem : $pages pages -> $pdfOutput"
        } finally {
            if ($null -ne $wordDoc) { $wordDoc.Close(0) }
        }
    }
} finally {
    $wordApp.Quit()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($wordApp) | Out-Null
}
