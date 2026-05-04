$files = @('start.sh', 'startup_hf.sh')
foreach ($f in $files) {
    $path = Join-Path $PSScriptRoot $f
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
    Write-Host "Fixed line endings: $f"
}
