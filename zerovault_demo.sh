#!/bin/bash
# ZeroVault Comprehensive Demo Script
# This script demonstrates all features of the ZeroVault encryption tool

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
RESET="\033[0m"

# Function to display section headers
section() {
    echo -e "\n${BOLD}${BLUE}==== $1 ====${RESET}\n"
}

# Function to display command being executed
show_command() {
    echo -e "${YELLOW}$ $1${RESET}"
}

# Function to run command and display output
run_command() {
    show_command "$1"
    echo -e "${CYAN}"
    eval "$1"
    echo -e "${RESET}"
}

# Function to create a divider
divider() {
    echo -e "${MAGENTA}----------------------------------------${RESET}"
}

# Check if zerovault is installed
if ! command -v zerovault &> /dev/null; then
    echo -e "${RED}Error: zerovault command not found.${RESET}"
    echo "Please make sure ZeroVault is installed and in your PATH."
    echo "You can install it by running 'cargo install --path .' from the project directory."
    exit 1
fi

# Create a temporary directory for the demo
DEMO_DIR=$(mktemp -d -t zerovault-demo-XXXXXX)
echo -e "${GREEN}Created temporary directory for demo: ${DEMO_DIR}${RESET}"
cd "$DEMO_DIR" || exit 1

# Clean up on exit
trap 'echo -e "${GREEN}Cleaning up...${RESET}"; rm -rf "$DEMO_DIR"' EXIT

section "Creating Test Files"
echo "Creating various test files for encryption..."

# Create a simple text file
echo "This is a simple text file with sensitive information." > simple.txt
run_command "cat simple.txt"

# Create a larger text file
cat > document.txt << EOF
CONFIDENTIAL MEMO
Date: April 23, 2025
To: Executive Team
From: CEO

Subject: Strategic Roadmap 2025-2027

This document outlines our confidential strategic plan for the next two years.
Key initiatives include:

1. Market Expansion into APAC region
2. New Product Launch in Q3 2025
3. Acquisition of smaller competitors
4. R&D investment increase by 15%

Please keep this information strictly confidential.
EOF
run_command "cat document.txt"

# Create a binary file
dd if=/dev/urandom of=binary.dat bs=1K count=10 2>/dev/null
run_command "ls -lh binary.dat"

section "Basic Encryption"
echo "Demonstrating basic file encryption with various options..."

# Basic encryption with default settings
run_command "zerovault encrypt --input simple.txt --password demo_password --non-interactive"
run_command "ls -lh simple.txt.vault"

# Encryption with a comment
run_command "zerovault encrypt --input document.txt --password demo_password --comment \"Confidential strategic document\" --non-interactive"
run_command "ls -lh document.txt.vault"

# Encryption with custom output path
run_command "zerovault encrypt --input binary.dat --output encrypted_binary.vault --password demo_password --non-interactive"
run_command "ls -lh encrypted_binary.vault"

# Encryption with verbose output
run_command "zerovault encrypt --input simple.txt --output simple_verbose.vault --password demo_password --verbose --non-interactive"

section "File Information"
echo "Retrieving information about encrypted vault files..."

# Display info about a vault file
run_command "zerovault info --input document.txt.vault"

# Display info with JSON output
run_command "zerovault info --input document.txt.vault --json"

section "File Validation"
echo "Validating vault file integrity..."

# Validate a vault file
run_command "zerovault validate --input simple.txt.vault"

# Try to validate a non-vault file
echo "Invalid content" > not_a_vault.txt
run_command "zerovault validate --input not_a_vault.txt || echo 'Validation failed as expected'"

section "File Decryption"
echo "Decrypting files with various options..."

# Basic decryption
run_command "zerovault decrypt --input simple.txt.vault --output simple_decrypted.txt --password demo_password --non-interactive"
run_command "cat simple_decrypted.txt"

# Decryption with verification of contents
run_command "diff -s simple.txt simple_decrypted.txt"

# Decryption with verbose output
run_command "zerovault decrypt --input document.txt.vault --output document_decrypted.txt --password demo_password --verbose --non-interactive"
run_command "cat document_decrypted.txt"

# Attempt decryption with wrong password
run_command "zerovault decrypt --input encrypted_binary.vault --output binary_wrong.dat --password wrong_password --non-interactive || echo 'Decryption failed as expected with wrong password'"

section "Stream Processing"
echo "Demonstrating stream encryption and decryption..."

# Stream encryption
run_command "echo 'This is data for stream encryption' | zerovault encrypt-stream --password stream_password > stream.vault"
run_command "ls -lh stream.vault"

# Stream decryption
run_command "cat stream.vault | zerovault decrypt-stream --password stream_password"

# Stream encryption of a file
run_command "cat document.txt | zerovault encrypt-stream --password stream_password > document_stream.vault"

# Stream decryption to a file
run_command "cat document_stream.vault | zerovault decrypt-stream --password stream_password > document_stream_decrypted.txt"
run_command "diff -s document.txt document_stream_decrypted.txt"

section "Force Overwrite"
echo "Demonstrating force overwrite functionality..."

# Try encryption without force flag (should fail if file exists)
run_command "zerovault encrypt --input simple.txt --output simple_existing.vault --password demo_password --non-interactive"
run_command "zerovault encrypt --input simple.txt --output simple_existing.vault --password demo_password --non-interactive || echo 'Encryption failed as expected (file exists)'"

# Use force flag to overwrite
run_command "zerovault encrypt --input simple.txt --output simple_existing.vault --password demo_password --force --non-interactive"

section "Metadata and Comments"
echo "Examining metadata and comments in vault files..."

# Create file with comment
run_command "zerovault encrypt --input document.txt --output document_with_comment.vault --password demo_password --comment \"Top secret information\" --non-interactive"

# View metadata and comments
run_command "zerovault info --input document_with_comment.vault"

# View metadata in JSON format
run_command "zerovault info --input document_with_comment.vault --json | grep -A 10 metadata"

section "Self-Tests"
echo "Running ZeroVault's built-in self-tests..."

# Run self-tests
run_command "zerovault test"

section "Interactive Mode"
echo "Interactive mode demonstration..."
echo "For this section, you would normally interact with the prompts."
echo "Since this is a non-interactive script, we'll just show the commands."

divider
echo -e "${YELLOW}$ zerovault encrypt${RESET}"
echo -e "${CYAN}Enter input file path: document.txt"
echo "Enter output file path [document.txt.vault]: special_vault.vault"
echo "Enter encryption password: ********"
echo "Confirm password: ********"
echo "Enter comment (optional): This is a special document"
echo "✓ File encrypted successfully"
echo "  Input: document.txt"
echo "  Output: special_vault.vault"
echo "  Size: 350 bytes"
echo "  Comment: This is a special document${RESET}"
divider

echo -e "${YELLOW}$ zerovault decrypt${RESET}"
echo -e "${CYAN}Enter vault file path: special_vault.vault"
echo "Enter output file path [document_decrypted.txt]: "
echo "Enter decryption password: ********"
echo "✓ File decrypted successfully"
echo "  Input: special_vault.vault"
echo "  Output: document_decrypted.txt"
echo "  Size: 350 bytes${RESET}"
divider

section "Error Handling Examples"
echo "Demonstrating how ZeroVault handles various errors..."

# Try to decrypt a non-existent file
run_command "zerovault decrypt --input nonexistent_file.vault --password demo_password --non-interactive || echo 'Error handled successfully'"

# Try to encrypt to a directory
mkdir test_directory
run_command "zerovault encrypt --input simple.txt --output test_directory --password demo_password --non-interactive || echo 'Error handled successfully'"

# Try to validate an invalid file
echo "This is not a valid vault file" > invalid.vault
run_command "zerovault validate --input invalid.vault || echo 'Error handled successfully'"

section "JSON Output for Scripting"
echo "Demonstrating JSON output for programmatic usage..."

# Various commands with JSON output
run_command "zerovault encrypt --input simple.txt --output json_output.vault --password demo_password --non-interactive --json"
run_command "zerovault validate --input json_output.vault --json"
run_command "zerovault info --input json_output.vault --json"

section "Batch Processing"
echo "Demonstrating batch processing of multiple files..."

# Create multiple test files
mkdir batch_files
for i in {1..5}; do
  echo "Content for file $i" > "batch_files/file$i.txt"
done

# Batch encryption script
cat > batch_encrypt.sh << 'EOF'
#!/bin/bash
for file in batch_files/*.txt; do
  zerovault encrypt --input "$file" --password batch_password --non-interactive
done
EOF
chmod +x batch_encrypt.sh
run_command "./batch_encrypt.sh"
run_command "ls -la batch_files/"

# Batch validation script
cat > batch_validate.sh << 'EOF'
#!/bin/bash
for vault in batch_files/*.vault; do
  echo "Validating $vault..."
  zerovault validate --input "$vault"
done
EOF
chmod +x batch_validate.sh
run_command "./batch_validate.sh"

section "Advanced Use Cases"
echo "Demonstrating advanced use cases..."

# Layered encryption (encrypt already encrypted data)
run_command "zerovault encrypt --input simple.txt.vault --output double_encrypted.vault --password outer_password --comment \"Nested encryption demo\" --non-interactive"
run_command "zerovault info --input double_encrypted.vault"

# Checksum verification
run_command "sha256sum simple.txt > simple.txt.sha256"
run_command "cat simple.txt.sha256"
run_command "zerovault encrypt --input simple.txt.sha256 --output checksum.vault --password checksum_password --non-interactive"
run_command "zerovault decrypt --input checksum.vault --output checksum_verified.sha256 --password checksum_password --non-interactive"
run_command "cat checksum_verified.sha256"

# Timestamp verification
cat > timestamp_demo.sh << 'EOF'
#!/bin/bash
echo "Creating a timestamped document..."
echo "Document created on $(date)" > timestamped.txt
zerovault encrypt --input timestamped.txt --output timestamped.vault --password time_password --comment "Timestamp verification demo" --non-interactive
zerovault info --input timestamped.vault
EOF
chmod +x timestamp_demo.sh
run_command "./timestamp_demo.sh"

section "Help and Version Information"
echo "Viewing help and version information..."

# Help command
run_command "zerovault --help"

# Version information
run_command "zerovault --version"

# Subcommand help
run_command "zerovault encrypt --help"
run_command "zerovault decrypt --help"
run_command "zerovault info --help"

echo -e "\n${GREEN}${BOLD}Demo completed successfully!${RESET}"
echo -e "You've seen all major features of ZeroVault in action."
echo -e "For more information, refer to the README.md file or run ${YELLOW}zerovault --help${RESET}"
echo -e "\nTemporary files will be cleaned up automatically."