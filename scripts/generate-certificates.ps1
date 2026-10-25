# SSL/TLS Certificate Generation Script for Blackbook (PowerShell)
# Generates a self-signed certificate for development/testing
# Source: scripts/generate-certificates.ps1
# Usage: .\scripts\generate-certificates.ps1 -CertDir ".\.certs" -CertName "server"
#
# Runs in Windows PowerShell 5.1 and PowerShell 7, with any OpenSSL build. The
# OpenSSL config is written to a temp file and passed with -config, because
# some Windows builds (Strawberry Perl's, for one) point at a default
# openssl.cnf that doesn't exist, and `openssl req` refuses to run without one.
# Keep this file ASCII-only: Windows PowerShell 5.1 reads a script without a
# BOM as ANSI, and a multi-byte character can turn into a stray quote.

param(
    [string]$CertDir = ".\.certs",
    [string]$CertName = "server",
    [int]$DaysValid = 365,
    [int]$KeySize = 2048
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Success { Write-Host "[ok] $args" -ForegroundColor Green }
function Write-Warning { Write-Host "[!] $args" -ForegroundColor Yellow }
function Write-Info { Write-Host "-> $args" -ForegroundColor Cyan }
function Write-Header { Write-Host "=== $args ===" -ForegroundColor Cyan }

# Run openssl; if it fails, throw with OpenSSL's own error output.
function Invoke-OpenSsl([string]$What, [string[]]$OpenSslArgs) {
    # Under "Stop", Windows PowerShell 5.1 treats any native stderr output as
    # a terminating error, so let openssl write to stderr and judge it by its
    # exit code instead.
    $ErrorActionPreference = "Continue"
    $output = & openssl @OpenSslArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to $What (openssl exit code $LASTEXITCODE):`n  $($output -join "`n  ")"
    }
}

Write-Header "Blackbook SSL/TLS Certificate Generator"
Write-Host "Generating self-signed certificates for development/testing" -ForegroundColor Yellow
Write-Host ""

# Create directory if it doesn't exist
if (-not (Test-Path -Path $CertDir)) {
    New-Item -ItemType Directory -Path $CertDir | Out-Null
    Write-Success "Created certificate directory: $CertDir"
}

# Check if certificates already exist
if ((Test-Path -Path "$CertDir\$CertName.crt") -and (Test-Path -Path "$CertDir\$CertName.key")) {
    Write-Warning "Certificates already exist:"
    Write-Host "  Certificate: $CertDir\$CertName.crt"
    Write-Host "  Private Key: $CertDir\$CertName.key"
    Write-Host ""

    $response = Read-Host "Overwrite existing certificates? (y/n)"
    if ($response -ne "y" -and $response -ne "Y") {
        Write-Host "Cancelled. Using existing certificates."
        exit 0
    }
}

Write-Host "Generating certificate with the following parameters:" -ForegroundColor Cyan
Write-Host "  Certificate Directory: $CertDir"
Write-Host "  Certificate Name: $CertName"
Write-Host "  Validity Period: $DaysValid days"
Write-Host "  Key Size: $KeySize bits"
Write-Host ""

# Check if OpenSSL is available
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: OpenSSL is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install OpenSSL: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Red
    exit 1
}
Write-Success "OpenSSL found: $(openssl version)"

# Get paths ($CertDir is kept as given, for the docker-compose hint below)
$CertPath = (Resolve-Path -Path $CertDir).ProviderPath
$KeyFile = Join-Path -Path $CertPath -ChildPath "$CertName.key"
$CertFile = Join-Path -Path $CertPath -ChildPath "$CertName.crt"
$ConfigFile = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "blackbook-openssl-$([guid]::NewGuid()).cnf"

# Subject and extensions. Modern TLS clients ignore the CN and match only the
# subjectAltName, so the names to serve go there.
$config = @"
[req]
prompt             = no
distinguished_name = dn
x509_extensions    = v3

[dn]
C            = US
ST           = State
L            = City
O            = Organization
CN           = blackbook.local
emailAddress = admin@blackbook.local

[v3]
basicConstraints     = critical, CA:FALSE
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = DNS:blackbook.local, DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = hash
"@

try {
    [IO.File]::WriteAllText($ConfigFile, ($config -replace "`r`n", "`n"))

    # Generate private key
    Write-Info "Generating private key..."
    Invoke-OpenSsl "generate the private key" @("genrsa", "-out", $KeyFile, "$KeySize")
    Write-Success "Private key generated"

    # Generate self-signed certificate (no CSR needed when self-signing)
    Write-Info "Generating self-signed certificate..."
    Invoke-OpenSsl "generate the self-signed certificate" @(
        "req", "-new", "-x509", "-key", $KeyFile, "-out", $CertFile,
        "-days", "$DaysValid", "-sha256", "-config", $ConfigFile)
    Write-Success "Self-signed certificate generated"

    # Display certificate information
    Write-Host ""
    Write-Host "Certificate Details:" -ForegroundColor Yellow
    openssl x509 -text -noout -in $CertFile | Select-String "Subject:|Issuer:|Public-Key:|Not Before|Not After|DNS:" | ForEach-Object { Write-Host "  $($_.Line.Trim())" }

    Write-Host ""
    Write-Header "Certificate Generation Complete"
    Write-Host ""
    Write-Host "Certificate files:"
    Write-Success "$CertFile"
    Write-Success "$KeyFile"
    Write-Host ""
    Write-Host "SECURITY NOTE:" -ForegroundColor Yellow
    Write-Host "  These are self-signed development certificates."
    Write-Host "  For production, use certificates from a trusted Certificate Authority."
    Write-Host "  Update docker-compose.yml to mount proper certificates."
    Write-Host ""
    Write-Host "Usage in docker-compose.yml:" -ForegroundColor Cyan
    $composeDir = ($CertDir -replace '\\', '/') -replace '^\./', ''
    Write-Host "  volumes:"
    Write-Host "    - ./$composeDir/$CertName.crt:/opt/blackbook/certs/server.crt:ro"
    Write-Host "    - ./$composeDir/$CertName.key:/opt/blackbook/certs/server.key:ro"
    Write-Host ""

} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    exit 1
} finally {
    Remove-Item -Path $ConfigFile -ErrorAction SilentlyContinue
}
