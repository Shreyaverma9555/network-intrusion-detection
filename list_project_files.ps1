$projectRoot = $PSScriptRoot

Write-Host ""
Write-Host "Network Intrusion Detection Project Files"
Write-Host "Project: $projectRoot"
Write-Host ""

Get-ChildItem -LiteralPath $projectRoot -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\__pycache__\\|\.pyc$' } |
    ForEach-Object { $_.FullName.Substring($projectRoot.Length + 1) } |
    Sort-Object
