# Deploy SAM to Hostinger via FTP
# Usage: .\deploy.ps1 index.html    (deploy single file)
#        .\deploy.ps1               (deploy all files)

$creds = @{}
Get-Content "$PSScriptRoot\.ftp-credentials" | ForEach-Object {
    if ($_ -match "^(\w+)=(.+)$") { $creds[$Matches[1]] = $Matches[2] }
}
$ftpHost    = $creds["FTP_HOST"]
$ftpUser    = $creds["FTP_USER"]
$ftpPass    = $creds["FTP_PASS"]
$ftpPort    = $creds["FTP_PORT"]
$remotePath = $creds["FTP_REMOTE_PATH"]
$local      = $PSScriptRoot

# Write netrc to temp file so password special chars aren't interpreted by shell
$netrcFile = "$env:TEMP\.netrc-sam"
"machine $ftpHost login $ftpUser password $ftpPass" | Out-File -FilePath $netrcFile -Encoding ascii

$exclude = @(".git", ".ftp-credentials", "deploy.ps1", "CLAUDE.md", "README.md")

function Should-Exclude($path) {
    foreach ($ex in $exclude) {
        if ((Split-Path $path -Leaf) -like $ex) { return $true }
        if ($path -like "*\$ex\*") { return $true }
    }
    return $false
}

function Deploy-File($rel) {
    $localPath  = Join-Path $local $rel
    $relForward = $rel -replace "\\", "/"
    $url = if ($remotePath) { "ftp://${ftpHost}:${ftpPort}/${remotePath}/${relForward}" } else { "ftp://${ftpHost}:${ftpPort}/${relForward}" }
    Write-Host "Uploading $rel ..." -ForegroundColor Cyan
    $out = & curl.exe --ssl --insecure --ftp-create-dirs --netrc-file $netrcFile -T $localPath $url 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK" -ForegroundColor Green }
    else { Write-Host "  FAILED: $out" -ForegroundColor Red }
}

# Auto-increment version and date in index.html before deploying
function Update-Version {
    $indexPath = Join-Path $local "index.html"
    $content = [System.IO.File]::ReadAllText($indexPath, [System.Text.Encoding]::UTF8)
    if ($content -match 'id="app-version">(\d+)\.(\d+)<') {
        $major   = [int]$Matches[1]
        $minor   = [int]$Matches[2] + 1
        $ver     = "$major.$minor"
        $dateStr = Get-Date -Format "MMM d, yyyy h:mm tt"
        $content = $content -replace '(?<=id="app-version">)[^<]+', $ver
        $content = $content -replace '(?<=id="app-build-date">)[^<]+', $dateStr
        # Also update Settings version fields
        $content = $content -replace '(inp-version-major.*?value=")[^"]*', "`${1}$major"
        $content = $content -replace '(inp-version-minor.*?value=")[^"]*', "`${1}$minor"
        [System.IO.File]::WriteAllText($indexPath, $content, [System.Text.Encoding]::UTF8)
        Write-Host "  Version bumped to $ver  |  Date: $dateStr" -ForegroundColor Cyan
    }
}

# Single file mode
if ($args.Count -gt 0) {
    if ($args[0] -eq "index.html") { Update-Version }
    Deploy-File $args[0]
    Remove-Item $netrcFile -Force -ErrorAction SilentlyContinue
    exit
}

# Full deploy
Update-Version
Write-Host "Deploying all SAM files to $ftpHost/$remotePath ..." -ForegroundColor Yellow
$files = Get-ChildItem -Path $local -Recurse -File | Where-Object { -not (Should-Exclude $_.FullName) }
$i = 0
foreach ($file in $files) {
    $i++
    $rel = $file.FullName.Substring($local.Length + 1)
    Write-Progress -Activity "Deploying" -Status "$i of $($files.Count): $rel" -PercentComplete (($i / $files.Count) * 100)
    Deploy-File $rel
}
Remove-Item $netrcFile -Force -ErrorAction SilentlyContinue
Write-Host "Deploy complete." -ForegroundColor Green
