#!/bin/bash
# SSL/TLS Certificate Generation Script for Blackbook
# Generates self-signed certificates for development/testing
# Source: scripts/generate-certificates.sh

set -e

# Configuration
CERT_DIR="${1:-.certs}"
CERT_NAME="${2:-server}"
DAYS_VALID="${3:-365}"
KEY_SIZE="${4:-2048}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Blackbook SSL/TLS Certificate Generator ===${NC}"
echo "Generating self-signed certificates for development/testing"
echo ""

# Create directory if it doesn't exist
if [ ! -d "$CERT_DIR" ]; then
    mkdir -p "$CERT_DIR"
    echo -e "${GREEN}✓${NC} Created certificate directory: $CERT_DIR"
fi

# Check if certificates already exist
if [ -f "$CERT_DIR/$CERT_NAME.crt" ] && [ -f "$CERT_DIR/$CERT_NAME.key" ]; then
    echo -e "${YELLOW}⚠${NC} Certificates already exist:"
    echo "  Certificate: $CERT_DIR/$CERT_NAME.crt"
    echo "  Private Key: $CERT_DIR/$CERT_NAME.key"
    echo ""
    read -p "Overwrite existing certificates? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled. Using existing certificates."
        exit 0
    fi
fi

echo "Generating certificate with the following parameters:"
echo "  Certificate Directory: $CERT_DIR"
echo "  Certificate Name: $CERT_NAME"
echo "  Validity Period: $DAYS_VALID days"
echo "  Key Size: $KEY_SIZE bits"
echo ""

# Generate private key
echo -e "${YELLOW}→${NC} Generating private key..."
openssl genrsa -out "$CERT_DIR/$CERT_NAME.key" "$KEY_SIZE" 2>/dev/null
echo -e "${GREEN}✓${NC} Private key generated"

# Generate certificate signing request
echo -e "${YELLOW}→${NC} Generating certificate signing request..."
openssl req -new \
    -key "$CERT_DIR/$CERT_NAME.key" \
    -out "$CERT_DIR/$CERT_NAME.csr" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=blackbook.local/emailAddress=admin@blackbook.local" \
    2>/dev/null
echo -e "${GREEN}✓${NC} Certificate signing request generated"

# Generate self-signed certificate
echo -e "${YELLOW}→${NC} Generating self-signed certificate..."
openssl x509 -req \
    -days "$DAYS_VALID" \
    -in "$CERT_DIR/$CERT_NAME.csr" \
    -signkey "$CERT_DIR/$CERT_NAME.key" \
    -out "$CERT_DIR/$CERT_NAME.crt" \
    -sha256 \
    2>/dev/null
echo -e "${GREEN}✓${NC} Self-signed certificate generated"

# Clean up CSR
rm -f "$CERT_DIR/$CERT_NAME.csr"

# Set secure permissions
chmod 400 "$CERT_DIR/$CERT_NAME.key"
chmod 444 "$CERT_DIR/$CERT_NAME.crt"
echo -e "${GREEN}✓${NC} Set secure file permissions"

# Display certificate information
echo ""
echo -e "${YELLOW}Certificate Details:${NC}"
openssl x509 -text -noout -in "$CERT_DIR/$CERT_NAME.crt" | grep -A 2 "Subject:"
openssl x509 -text -noout -in "$CERT_DIR/$CERT_NAME.crt" | grep -A 2 "Issuer:"
openssl x509 -text -noout -in "$CERT_DIR/$CERT_NAME.crt" | grep -A 2 "Public-Key:"
openssl x509 -text -noout -in "$CERT_DIR/$CERT_NAME.crt" | grep -A 2 "Not Before\|Not After"

echo ""
echo -e "${GREEN}=== Certificate Generation Complete ===${NC}"
echo ""
echo "Certificate files:"
echo -e "  ${GREEN}✓${NC} $CERT_DIR/$CERT_NAME.crt"
echo -e "  ${GREEN}✓${NC} $CERT_DIR/$CERT_NAME.key"
echo ""
echo "⚠️  SECURITY NOTE:"
echo "  These are self-signed development certificates."
echo "  For production, use certificates from a trusted Certificate Authority."
echo "  Update docker-compose.yml to mount proper certificates."
echo ""
echo "Usage in docker-compose.yml:"
echo "  volumes:"
echo "    - ./$CERT_DIR/$CERT_NAME.crt:/opt/blackbook/certs/server.crt:ro"
echo "    - ./$CERT_DIR/$CERT_NAME.key:/opt/blackbook/certs/server.key:ro"
echo ""
