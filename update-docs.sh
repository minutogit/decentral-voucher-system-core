#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

echo "Generating documentation in default location (target/doc)..."

# Define the output and source directories.
OUTPUT_DIR="docs/api"
DOC_SOURCE_DIR="target/doc"

# Generate the documentation using cargo doc.
# The flag '--features unstable-doc-base' was removed as it's not defined in this project.
cargo doc --no-deps --lib

echo "Documentation generated."
echo "Preparing to move documentation to $OUTPUT_DIR..."

# Ensure the output directory exists and is empty to prevent stale files.
if [ -d "$OUTPUT_DIR" ]; then
    echo "Removing old documentation from: $OUTPUT_DIR"
    rm -rf "$OUTPUT_DIR"
fi
echo "Creating directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Copy the generated documentation from the source directory to the output directory.
# The `.` at the end of the source path ensures that hidden files are also copied.
cp -a "$DOC_SOURCE_DIR/." "$OUTPUT_DIR/"

echo "Documentation successfully updated in $OUTPUT_DIR"