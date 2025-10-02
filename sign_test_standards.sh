#!/bin/bash
#
# sign_test_standards.sh
#
# Dieses Skript signiert alle Gutschein-Standard-Definitionen, die
# ausschließlich für die Test-Suite verwendet werden. Es stellt sicher,
# dass die Testdaten immer auf dem neuesten Stand sind, insbesondere nach
# Änderungen am `voucher-cli`-Tool oder dem User-ID-Format.

# Stellt sicher, dass das Skript bei einem Fehler sofort abbricht.
set -e

# Definiert den Pfad zur Schlüsseldatei, die auch für die "echten" Standards verwendet wird.
KEY_FILE="target/dev-keys/issuer.key"

echo "--- Test-Standard Signatur-Skript ---"

# 1. Überprüfen, ob die Schlüsseldatei existiert.
if [ ! -f "$KEY_FILE" ]; then
  echo "❌ FEHLER: Schlüsseldatei unter '$KEY_FILE' nicht gefunden."
  echo "   Bitte führe zuerst das Haupt-Skript 'sign_standards.sh' aus, um Schlüssel zu generieren."
  exit 1
else
  echo "🔑 Schlüsseldatei unter '$KEY_FILE' gefunden."
fi

# 2. Alle '*.toml'-Dateien im Testdaten-Verzeichnis finden und signieren.
echo ""
echo "✍️  Suche nach Test-Standards zum Signieren..."
for standard_file in tests/test_data/standards/*.toml; do
  if [ -f "$standard_file" ]; then
    echo ""
    # Das Rust-CLI-Tool aufrufen, um jede gefundene Datei zu signieren.
    cargo run --bin voucher-cli -- sign-standard --key "$KEY_FILE" "$standard_file"
  fi
done

echo ""
echo "✅ Alle Test-Standards wurden erfolgreich neu signiert."