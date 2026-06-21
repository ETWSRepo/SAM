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

$exclude = @(".git", ".ftp-credentials", "deploy.ps1", "CLAUDE.md", "README.md", "node_modules", "run-tests.js", "package.json", "package-lock.json")

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

# Bake the deploy date directly into the footer span at deploy time.
# This is the authoritative source the app reads — no JS/Settings sync needed.
function Update-Version {
    $indexPath = Join-Path $local "index.html"
    $content = [System.IO.File]::ReadAllText($indexPath, [System.Text.Encoding]::UTF8)
    $deployDate = Get-Date -Format "MMM d, yyyy h:mm tt"
    # Footer span (authoritative): <span id="app-deploy-date">...</span>
    $content = $content -replace '(?<=id="app-deploy-date">)[^<]*', $deployDate
    # Keep the Settings input data attribute in sync too
    $content = $content -replace '(inp-deploy-date.*?data-deploy-date=")[^"]*', "`${1}$deployDate"
    # Test environment marker — ensure the home title ends with " - Test"
    # (idempotent: strips any existing " - Test" first, so re-deploys don't stack)
    $content = $content -replace '(>Silent Auction Manager \(SAM\))( - Test)?(</h1>)', '${1} - Test${3}'
    [System.IO.File]::WriteAllText($indexPath, $content, [System.Text.Encoding]::UTF8)
    Write-Host "  Deployed: $deployDate" -ForegroundColor Cyan
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
