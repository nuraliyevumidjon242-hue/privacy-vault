$ErrorActionPreference = "Stop"
$envFile = Join-Path (Get-Location) ".env"
$template = Join-Path (Get-Location) ".env.example"

if (Test-Path $envFile) {
    throw ".env already exists. Refusing to overwrite secrets."
}
if (-not (Test-Path $template)) {
    throw ".env.example was not found. Run this script from the project root."
}

function New-SecretHex {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
}

$content = Get-Content $template -Raw
$databasePassword = New-SecretHex
$content = $content.Replace("PRIVACYVAULT_MASTER_KEY=", "PRIVACYVAULT_MASTER_KEY=$(New-SecretHex)")
$content = $content.Replace("PRIVACYVAULT_BLIND_INDEX_KEY=", "PRIVACYVAULT_BLIND_INDEX_KEY=$(New-SecretHex)")
$content = $content.Replace("PRIVACYVAULT_PSEUDONYM_KEY=", "PRIVACYVAULT_PSEUDONYM_KEY=$(New-SecretHex)")
$content = $content.Replace("PRIVACYVAULT_JWT_SECRET=", "PRIVACYVAULT_JWT_SECRET=$(New-SecretHex)")
$content = $content.Replace("POSTGRES_PASSWORD=replace-with-a-strong-local-password",
    "POSTGRES_PASSWORD=$databasePassword")
$content = $content.Replace("DB_PASSWORD=replace-with-a-strong-local-password",
    "DB_PASSWORD=$databasePassword")
Set-Content -Path $envFile -Value $content -NoNewline
Write-Host "Created .env with unique random development secrets. Keep it private."
