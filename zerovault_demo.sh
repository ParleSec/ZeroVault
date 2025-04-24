#!/bin/bash
# ZeroVault Comprehensive Demo Script
# This script demonstrates all features of the ZeroVault encryption tool

# Text styling for better readability
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# Helper functions
section() {
    echo -e "\n${BOLD}${BLUE}===== $1 =====${RESET}\n"
}

cmd() {
    echo -e "${YELLOW}$ $1${RESET}"
    eval "$1"
    echo ""
}

# Check if ZeroVault is installed
if ! command -v zerovault &> /dev/null; then
    echo -e "${RED}Error: zerovault command not found${RESET}"
    echo "Please install ZeroVault first:"
    echo "1. Navigate to the ZeroVault project directory"
    echo "2. Run: cargo install --path ."
    exit 1
fi

# Setup temp directory for the demo
DEMO_DIR=$(mktemp -d -t zerovault-demo-XXXXXX)
echo -e "${GREEN}Created temporary directory: ${DEMO_DIR}${RESET}"
cd "$DEMO_DIR" || exit 1

# Clean up on exit
trap 'echo -e "${GREEN}Cleaning up temporary files...${RESET}"; rm -rf "$DEMO_DIR"' EXIT

section "Creating Sample Data"

# Create a simple text file
echo "This is a simple text file with confidential information." > secret.txt
cmd "cat secret.txt"

# Create a more complex document
cat > document.txt << EOF
CONFIDENTIAL MEMO
Date: April 24, 2025
Subject: Project Phoenix Roadmap

This document contains sensitive information about our upcoming product launch.
Key points:
1. Target launch date: September 15, 2025
2. Initial markets: North America, Europe, Asia
3. Projected first-year revenue: $25M

DO NOT SHARE THIS DOCUMENT.
EOF

cmd "cat document.txt"

# Create a binary file
dd if=/dev/urandom of=data.bin bs=1K count=5 2>/dev/null
cmd "ls -la data.bin"

section "Basic Encryption"

# Encrypt the text file
cmd "zerovault encrypt --input secret.txt --password demo123 --non-interactive"
cmd "ls -la secret.txt.vault"

# Encrypt with comment
cmd "zerovault encrypt --input document.txt --password demo123 --comment \"Confidential roadmap\" --non-interactive"

# Custom output name
cmd "zerovault encrypt --input data.bin --output binary_data.vault --password demo123 --non-interactive"

section "Vault Information"

# Display vault information
cmd "zerovault info --input document.txt.vault"

# JSON output
cmd "zerovault info --input document.txt.vault --json"

section "Validation"

# Validate vault files
cmd "zerovault validate --input secret.txt.vault"

# Invalid file
echo "Not a valid vault file" > invalid.txt
cmd "zerovault validate --input invalid.txt || echo 'Validation failed as expected'"

section "Decryption"

# Decrypt file
cmd "zerovault decrypt --input secret.txt.vault --output decrypted_secret.txt --password demo123 --non-interactive"
cmd "cat decrypted_secret.txt"

# Verify content matches
cmd "diff -s secret.txt decrypted_secret.txt"

# Wrong password
cmd "zerovault decrypt --input document.txt.vault --output should_fail.txt --password wrong123 --non-interactive || echo 'Failed as expected - wrong password'"

section "Stream Processing"

# Stream encryption
cmd "echo 'Secret message for stream encryption' | zerovault encrypt-stream --password stream123 > stream.vault"

# Stream decryption
cmd "cat stream.vault | zerovault decrypt-stream --password stream123"

section "Batch Processing"

# Create test files
mkdir batch
for i in {1..3}; do
    echo "Content for file $i" > "batch/file$i.txt"
done

# Batch encryption
echo -e "${CYAN}Encrypting multiple files in batch:${RESET}"
for file in batch/*.txt; do
    cmd "zerovault encrypt --input \"$file\" --password batch123 --non-interactive"
done

cmd "ls -la batch/"

section "Advanced Features"

# Layered encryption (nested vault)
cmd "zerovault encrypt --input secret.txt.vault --output nested.vault --password outer123 --comment \"Nested encryption demo\" --non-interactive"
cmd "zerovault info --input nested.vault"

# Force overwrite
cmd "zerovault encrypt --input secret.txt --output exists.vault --password demo123 --non-interactive"
cmd "zerovault encrypt --input secret.txt --output exists.vault --password demo123 --non-interactive || echo 'Failed as expected - file exists'"
cmd "zerovault encrypt --input secret.txt --output exists.vault --password demo123 --force --non-interactive"

section "Self Tests"

# Run self-tests
cmd "zerovault test"

section "Help Information"

# Show help information
cmd "zerovault --help"
cmd "zerovault encrypt --help"

echo -e "\n${GREEN}${BOLD}Demo completed successfully!${RESET}"
echo -e "You've seen the major features of ZeroVault in action."
echo -e "For more details, refer to the README.md file."
