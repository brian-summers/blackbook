# SSL/TLS Certificate Generation Script for Blackbook (PowerShell)
# Generates self-signed certificates for development/testing
# Source: scripts/generate-certificates.ps1
# Usage: .\scripts\generate-certificates.ps1 -CertDir ".\.certs" -CertName "server"

param(
    [string]$CertDir = ".\.certs",
    [string]$CertName = "server",
    [int]$DaysValid = 365,
    [int]$KeySize = 2048
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Success { Write-Host "✓ $args" -ForegroundColor Green }
function Write-Warning { Write-Host "⚠ $args" -ForegroundColor Yellow }
function Write-Info { Write-Host "→ $args" -ForegroundColor Cyan }
function Write-Header { Write-Host "=== $args ===" -ForegroundColor Cyan }

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
try {
    $opensslVersion = openssl version 2>&1
    Write-Success "OpenSSL found: $opensslVersion"
} catch {
    Write-Host "ERROR: OpenSSL is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install OpenSSL: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Red
    exit 1
}

# Get paths
$CertDir = (Resolve-Path -Path $CertDir).ProviderPath
$KeyFile = Join-Path -Path $CertDir -ChildPath "$CertName.key"
$CertFile = Join-Path -Path $CertDir -ChildPath "$CertName.crt"
$CsrFile = Join-Path -Path $CertDir -ChildPath "$CertName.csr"

try {
    # Generate private key
    Write-Info "Generating private key..."
    openssl genrsa -out $KeyFile $KeySize 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Private key generated"
    } else {
        throw "Failed to generate private key"
    }

    # Generate certificate signing request
    Write-Info "Generating certificate signing request..."
    $subj = "/C=US/ST=State/L=City/O=Organization/CN=blackbook.local/emailAddress=admin@blackbook.local"
    openssl req -new `
        -key $KeyFile `
        -out $CsrFile `
        -subj $subj `
        2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Certificate signing request generated"
    } else {
        throw "Failed to generate certificate signing request"
    }

    # Generate self-signed certificate
    Write-Info "Generating self-signed certificate..."
    openssl x509 -req `
        -days $DaysValid `
        -in $CsrFile `
        -signkey $KeyFile `
        -out $CertFile `
        -sha256 `
        2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Self-signed certificate generated"
    } else {
        throw "Failed to generate self-signed certificate"
    }

    # Clean up CSR
    Remove-Item -Path $CsrFile -ErrorAction SilentlyContinue
    Write-Success "Cleaned up temporary files"

    # Display certificate information
    Write-Host ""
    Write-Host "Certificate Details:" -ForegroundColor Yellow
    openssl x509 -text -noout -in $CertFile | Select-String "Subject:|Issuer:|Public-Key:|Not Before|Not After" | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Header "Certificate Generation Complete"
    Write-Host ""
    Write-Host "Certificate files:"
    Write-Success "$CertFile"
    Write-Success "$KeyFile"
    Write-Host ""
    Write-Host "⚠️  SECURITY NOTE:" -ForegroundColor Yellow
    Write-Host "  These are self-signed development certificates."
    Write-Host "  For production, use certificates from a trusted Certificate Authority."
    Write-Host "  Update docker-compose.yml to mount proper certificates."
    Write-Host ""
    Write-Host "Usage in docker-compose.yml:" -ForegroundColor Cyan
    Write-Host "  volumes:"
    Write-Host "    - ./$CertDir/$CertName.crt:/opt/blackbook/certs/server.crt:ro"
    Write-Host "    - ./$CertDir/$CertName.key:/opt/blackbook/certs/server.key:ro"
    Write-Host ""

} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    exit 1
}
