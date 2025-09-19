#!/bin/bash

# Stellt sicher, dass das Skript bei einem Fehler sofort abbricht.
set -e

echo "--- Standard Validierungs-Skript ---"

# 1. Alle 'standard.toml'-Dateien in den Unterverzeichnissen von 'voucher_standards' finden und validieren.
echo ""
echo "🔍 Suche nach Standards zur Validierung..."
for standard_file in voucher_standards/*/standard.toml; do
  echo ""
  # Das Rust-CLI-Tool aufrufen, um jede gefundene Datei zu validieren.
  cargo run --bin validate-standard -- validate-standard "$standard_file"
done