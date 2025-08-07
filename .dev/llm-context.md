# llm-context.md für decentral-voucher-system-core

Dies ist die Kontextdatei für die Entwicklung der Rust-Core-Bibliothek `voucher_core`. Sie dient als "README für die KI", um ein umfassendes Verständnis des Projekts und seiner Anforderungen zu gewährleisten.

## 1. Projekt & Zweck
- **Projektname:** `voucher_core`
- **Zweck:** Implementierung der Kernlogik eines dezentralen, vertrauensbasierten elektronischen Gutschein-Zahlungssystems, wie im Konzeptpapier "Decentralized Trust-Based Electronic Voucher Payment System" von Sebastian Galek (24. Januar 2025).
- **Hauptziel:** Bereitstellung einer robusten, sicheren und performanten Bibliothek, die später über FFI (Foreign Function Interface) und WASM (WebAssembly) in anderen Umgebungen (z.B. Desktop-Anwendungen, Web-Clients) genutzt werden kann.
- **Kernfunktionalität:** Erstellung, Verwaltung und Verifizierung von digitalen Gutscheinen und deren Transaktionshistorie.

## 2. Tech-Stack

- **Sprache:** Rust
- **Zielplattformen:** FFI-kompatibel (für Bindings zu anderen Sprachen) und WASM-kompatibel (für Web-Anwendungen).
- **Kryptographie:** Standard-Rust-Kryptographie-Bibliotheken für digitale Signaturen und Hashing.

## 3. Architektur & Designprinzipien
- **Modulare Architektur:** Die Bibliothek soll in logische Module unterteilt werden (z.B. für Gutschein-Struktur, Transaktionen, Signaturen, Validierung).
- **Dezentraler Ansatz:** Das System basiert auf dezentralen Gutscheinen (Textdateien), die eine verkettete Liste der Transaktionshistorie enthalten (eine Art "Mini-Blockchain pro Gutschein").
- **Kein globales Ledger:** Im Gegensatz zu traditionellen Blockchains wird bewusst auf ein globales, verteiltes Ledger verzichtet. Die Integrität wird durch digitale Signaturen und soziale Kontrolle gewährleistet.
- **Offline-Fähigkeit:** Transaktionen sollen auch offline durchgeführt werden können, indem die aktualisierte Gutschein-Datei direkt an den neuen Halter übergeben wird.
- **Fokus auf Betrugserkennung, nicht -vermeidung:** Da es kein globales Ledger gibt, kann die Core-Bibliothek nicht verhindern, dass ein Nutzer widersprüchliche Transaktionshistorien (Double Spending) erzeugt. Das System stellt stattdessen sicher, dass jeder Betrugsversuch durch digitale Signaturen kryptographisch beweisbar ist, was eine Erkennung und soziale Sanktionen in einem übergeordneten System (Layer 2) ermöglicht.
- **Fokus auf Kernlogik:** Zunächst wird nur die grundlegende Funktionalität der Gutschein- und Transaktionsverwaltung implementiert. Die "Transaction Verification Layer" und "User Trust Verification Layer" (Layer 2 mit Servern) sollen *nicht* implementiert werden, aber die Struktur der Transaktionsketten sollte so optimiert werden, dass eine spätere Erweiterung um diese Layer möglich ist.
- **FFI/WASM-Kompatibilität:** Rust-Typen und -Funktionen müssen so gestaltet sein, dass sie einfach über FFI und WASM exponiert werden können (z.B. durch Verwendung von `#[no_mangle]`, C-kompatiblen Datentypen und `wasm_bindgen`).


## 4. Coding-Standards & Wichtige Regeln

- **Rust Best Practices:** Einhaltung der idiomatischen Rust-Programmierung, Fokus auf Sicherheit, Performance und Speichereffizienz.
- **Fehlerbehandlung:** Robuste Fehlerbehandlung mit Rusts `Result`-Typ.
- **Dokumentation:** Umfassende interne Dokumentation (Doc-Kommentare) für alle öffentlichen Funktionen und Strukturen.
- **Testen:** Umfassende Unit- und Integrationstests.
- **Keine externen Netzwerkaufrufe:** Die Core-Bibliothek soll keine direkten Netzwerkaufrufe für die Layer-2-Funktionalität enthalten. Diese Interaktionen werden von den übergeordneten Anwendungen gehandhabt, die `voucher_core` nutzen.

## 5. Kernkonzepte aus dem Paper (Zusammenfassung)
Gutschein-Struktur: Das universelle Gutschein-Container-Format
Ein Gutschein ist im Wesentlichen eine Textdatei (repräsentiert als JSON), die alle möglichen Informationen enthält, die ein Gutschein jemals haben könnte. Jede einzelne Gutscheininstitution wird in diesem einheitlichen JSON-Schema abgebildet. Die spezifischen Regeln und Eigenschaften eines Gutscheintyps (wie "Minuto-Gutschein" oder "Silber-Umlauf-Gutschein") werden in separaten **Standard-Definitionen** (`voucher_standard_definitions`) festgelegt.

Diese Definitionen werden als externe **TOML-Dateien** (z.B. aus einem `voucher_standards/`-Verzeichnis) bereitgestellt und zur Laufzeit geparst. Die TOML-Struktur ist klar in drei Blöcke unterteilt:
- **`[metadata]`**: Enthält allgemeine Informationen wie Name und UUID des Standards.
- **`[template]`**: Definiert Werte (z.B. die `unit` des Nennwerts), die bei der Erstellung eines neuen Gutscheins direkt in diesen kopiert werden.
- **`[validation]`**: Beinhaltet Regeln (z.B. `required_voucher_fields`, `guarantor_rules`), die zur Überprüfung eines Gutscheins verwendet werden.

```
{
  "voucher_standard": {
    "name": "STRING", // Der Name des Standards, zu dem dieser Gutschein gehört (z.B. "Minuto-Gutschein", "Silber-Umlauf-Gutschein").
    "uuid": "STRING"  // Die eindeutige Kennung (UUID) des Standards, zu dem dieser Gutschein gehört.
  },
  "voucher_id": "STRING", // Die eindeutige ID dieses spezifischen Gutscheins.
  "description": "STRING", // Eine allgemeine, menschenlesbare Beschreibung des Gutscheins (z.B. "Gutschein für 888 Minuten qualitativer Leistung").
  "divisible": "BOOLEAN", // Gibt an, ob der Gutschein in kleinere Einheiten aufgeteilt werden kann (true/false).
  "creation_date": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Das Erstellungsdatum des Gutscheins im ISO 8601-Format.
  "valid_until": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ",    // Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
  "non_redeemable_test_voucher": "BOOLEAN", // Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt (true/false).
  "nominal_value": { // Definiert den Wert, den der Gutschein repräsentiert.
    "unit": "STRING",     // Die Einheit des Gutscheinwerts (z.B. "Minuten", "Unzen", "Euro").
    "amount": "STRING",   // Die genaue Menge des Werts (z.B. "888", "1", "50"). Als String für Flexibilität bei Einheiten.
    "abbreviation": "STRING", // Eine gängige Abkürzung der Einheit (z.B. "m", "oz", "€").
    "description": "STRING" // Eine Beschreibung des Werts (z.B. "Objektive Zeit", "Physisches Silber", "Nationale Währung").
  },
  "collateral": { // Informationen zur Besicherung des Gutscheins.
    "type": "STRING",         // Die Art der Besicherung (z.B. "Physisches Edelmetall", "Community-Besicherung", "Fiat-Währung").
    "unit": "STRING",         // Die Einheit der Besicherung (z.B. "Unzen", "Euro").
    "amount": "STRING",       // Die Menge der Besicherung (z.B. "entspricht dem Nennwert", "200").
    "abbreviation": "STRING",// Eine gängige Abkürzung für die Besicherung (z.B. "oz", "€").
    "description": "STRING", // Eine detailliertere Beschreibung der Besicherung (z.B. "Edelmetall Silber, treuhänderisch verwahrt").
    "redeem_condition": "STRING" // **Extrem wichtig:** Bedingungen unter denen die Besicherung eingelöst/ausgezahlt werden kann (z.B. Notfallklausel).
  },
  "creator": { // Detaillierte Informationen zum Ersteller des Gutscheins.
    "id": "STRING",             // Eindeutige ID des Erstellers (oft ein Public Key).
    "first_name": "STRING",     // Vorname des Erstellers.
    "last_name": "STRING",      // Nachname des Erstellers.
    "address": {                // Detaillierte Adressinformationen des Erstellers.
      "street": "STRING",       // Straße.
      "house_number": "STRING", // Hausnummer.
      "zip_code": "STRING",     // Postleitzahl.
      "city": "STRING",         // Stadt.
      "country": "STRING",      // Land.
      "full_address": "STRING"  // Vollständige, formatierte Adresse.
    },
    "organization": "STRING",   // Die Organisation des Erstellers.
    "community": "STRING",      // Beschreibung der Gemeinschaft, zu der der Ersteller gehört.
    "phone": "STRING",          // Telefonnummer des Erstellers.
    "email": "STRING",          // E-Mail-Adresse des Erstellers.
    "url": "STRING",            // URL des Erstellers oder dessen Webseite.
    "gender": "STRING",         // Geschlecht des Erstellers ISO 5218 (1 = male", 2 = female", 0 = not known, 9 = Not applicable).
    "service_offer": "STRING",  // Beschreibt die Angebote oder Talente des Erstellers.
    "needs": "STRING",          // Beschreibt die Gesuche oder Bedürfnisse des Erstellers.
    "signature": "STRING",      // Die digitale Signatur des Erstellers. Sie signiert den Hash des initialen Gutschein-Objekts (ohne voucher_id, Signaturen und Transaktionen).
    "coordinates": "STRING"     // Geografische Koordinaten des Erstellers (z.B. "Breitengrad, Längengrad").
  },
  "guarantor_signatures": [ // Ein Array von Signaturen der Bürgen.
    { // Jede Signatur ist ein in sich geschlossenes, überprüfbares Objekt.
      "voucher_id": "STRING",         // Die ID des Gutscheins, zu dem diese Signatur gehört.
      "signature_id": "STRING",       // Eine eindeutige ID für dieses Signatur-Objekt, erzeugt durch Hashing der eigenen Metadaten.
      // Die Metadaten (alles außer signature_id und signature) werden kanonisiert und gehasht, um die signature_id zu erzeugen.
      "guarantor_id": "STRING",         // Eindeutige ID des Bürgen (aus Public Key).
      "first_name": "STRING",
      "last_name": "STRING",
      "organization": "STRING",
      "community": "STRING",
      "address": { // Vollständiges Adressobjekt, optional
      },
      "gender": "STRING", // ISO 5218
      "email": "STRING",
      "phone": "STRING",
      "coordinates": "STRING",
      "url": "STRING",
      "signature": "STRING",            // Die digitale Signatur des Bürgen, die die `signature_id` dieses Objekts unterzeichnet.
      "signature_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ" // Zeitpunkt der Bürgen-Signatur.
    }
  ],
  "needed_guarantors": "INTEGER", // Die Anzahl der für diesen Gutschein benötigten Bürgen.
  "transactions": [ // Eine chronologische Liste aller Transaktionen dieses Gutscheins.
    { // Jede Transaktion ist ein in sich geschlossenes, signiertes Objekt.
      "t_id": "STRING",                 // Eindeutige ID der Transaktion, erzeugt durch Hashing der Transaktionsdaten (ohne t_id und Signatur).
      "prev_hash": "STRING",            // Der Hash der vorherigen Transaktion (oder der voucher_id bei der "init"-Transaktion), der die Kette kryptographisch sichert.
      "t_type": "STRING",               // Art der Transaktion (z.B. "init" für Initialisierung, "split" für Teilung, "redeem" für Einlösung).
      "t_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Zeitpunkt der Transaktion.
      "sender_id": "STRING",            // ID des Senders der Transaktion.
      "recipient_id": "STRING",         // ID des Empfängers der Transaktion.
      "amount": "STRING",               // Der Betrag, der bei dieser Transaktion bewegt wurde.
      "sender_remaining_amount": "STRING",// Der Restbetrag beim Sender nach einer Teilung (nur bei "split").
      "sender_signature": "STRING"      // Digitale Signatur des Senders. Signiert ein Objekt, das aus prev_hash, sender_id, t_id und t_time besteht.
    }
  ],
  "additional_signatures": [ // Ein Array für zusätzliche, optionale Signaturen, die an den Gutschein angehängt werden können.
    {
      "voucher_id": "STRING",           // Die ID des Gutscheins, zu dem diese Signatur gehört.
      "signature_id": "STRING",       // Eine eindeutige ID für dieses Signatur-Objekt, erzeugt durch Hashing der eigenen Metadaten.
      "signer_id": "STRING",            // Eindeutige ID des zusätzlichen Unterzeichners (aus Public Key).
      "signature": "STRING",            // Die digitale Signatur, die die `signature_id` dieses Objekts unterzeichnet.
      "signature_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Zeitpunkt der Signatur.
      "description": "STRING"           // Eine Beschreibung, warum diese Signatur hinzugefügt wurde.
    }
  ]
}
```

### Transaktionskette

Die Transaktionen im `transactions`-Array bilden eine kryptographisch verkettete Liste, ähnlich einer Blockchain.

- **Verkettung:** Jede Transaktion enthält ein `prev_hash`-Feld.
  - Die erste Transaktion (`t_type: "init"`) hat einen `prev_hash`, der der Hash der `voucher_id` ist.
  - Jede nachfolgende Transaktion hat einen `prev_hash`, der der Hash der vollständigen, kanonisierten vorherigen Transaktion ist.
- **Integrität:** Jede Transaktion hat eine `t_id`, die aus dem Hash ihrer eigenen Daten (ohne `t_id` und `sender_signature`) erzeugt wird. Das stellt sicher, dass die Transaktionsdetails nicht nachträglich geändert werden können, ohne die `t_id` ungültig zu machen.
- **Authentizität:** Die `sender_signature` signiert ein separates Objekt, das die Kern-Metadaten der Transaktion (`prev_hash`, `sender_id`, `t_id`, `t_time`) enthält. Dies beweist, dass der Sender die Transaktion autorisiert hat und sie an einer bestimmten Stelle in der Kette verankert ist.

### Double-Spending-Erkennung (Basis-Layer)
Ein **Double Spend** liegt vor, wenn ein Nutzer von einem bestimmten Zustand des Gutscheins (repräsentiert durch den `prev_hash` der letzten gültigen Transaktion) zwei oder mehr unterschiedliche neue Transaktionen erstellt und diese an verschiedene Personen verteilt.

- **Erkennung:** Der Betrug ist kryptographisch nachweisbar, weil mehrere unterschiedliche Transaktionen existieren, die alle vom selben Sender (`sender_id`) signiert wurden und sich auf denselben `prev_hash` beziehen. Obwohl jede dieser Transaktionen für sich genommen eine gültige Signatur hat, ist die Existenz mehrerer "gültiger" Folgezustände der Beweis für den Betrug. Ein übergeordnetes System (Layer 2) kann dies durch die Suche nach doppelten Paaren von (`prev_hash`, `sender_id`) leicht aufdecken.
- **Beweisbarkeit:** Die digitale Signatur ermöglicht die eindeutige und unwiderlegbare Identifizierung des Betrügers.

#### Erkennung ohne Layer-2-Server (durch Pfad-Vereinigung)
Ein Double Spend kann auch ohne einen zentralen Server erkannt werden, wenn sich die aufgespaltenen Transaktionspfade bei einem späteren Nutzer wieder treffen. Da Gutscheine im System zirkulieren und oft beim Ersteller wieder eingelöst werden, ist dies ein praxisnaher Anwendungsfall.

- **Mechanismus:** Ein Nutzer, der einen Gutschein erhält, kann dessen Transaktionshistorie mit den Historien von bereits erhaltenen oder archivierten Gutscheinen vergleichen.
- **Beispiel:** Der ursprüngliche Ersteller eines Gutscheins erhält später zwei unterschiedliche Gutschein-Dateien zur Einlösung zurück. Beide leiten ihre Herkunft von seinem ursprünglichen Gutschein ab. Beim Vergleich der Historien stellt er fest, dass beide Dateien eine unterschiedliche Transaktion enthalten, die aber vom selben `prev_hash` abstammt. Damit ist der Double Spend bewiesen.
- **Voraussetzung:** Diese Methode erfordert, dass Nutzer (insbesondere Akteure wie Ersteller, die Einlösungen akzeptieren) alte Gutschein-Zustände vorhalten, um eine Vergleichsbasis zu haben.

### Weitere relevante Konzepte (für zukünftige Erweiterungen optimieren)
- **Teilzahlungen:** Ein Gutschein kann in kleinere Beträge aufgeteilt werden. Der Restbetrag verbleibt beim Sender, der daraus weitere Transaktionen erstellen kann.
- **Zusätzliche Signaturen:** Möglichkeit, weitere Signaturen (z.B. von Bürgen/Garanten) in die Gutschein-Datei zu integrieren.
- **Verschlüsselung:** Diffie-Hellman-Schlüsselaustausch zur Verschlüsselung von Transaktionsdateien während der Übertragung (später zu implementieren, aber die Datenstruktur sollte es ermöglichen).
- **Begrenzte Gültigkeitsdauer:** Gutscheine sollen nach einer bestimmten Zeit ihre Gültigkeit verlieren.
- **Keine Layer 2 Implementierung:** Die Logik für die "Transaction Verification Layer" (Server-basiertes Double-Spending-Matching) und die "User Trust Verification Layer" (Reputationsmanagement) wird in dieser Core-Bibliothek *nicht* implementiert. Die Datenstrukturen für Transaktionsketten sollen jedoch eine spätere Anbindung an solche Systeme ermöglichen.

## 6. Aktueller Projektstrukturbaum
```
├── Cargo.lock
├── Cargo.toml
├── examples
│   ├── playground_crypto_utils.rs
│   ├── playground_utils.rs
│   └── playground_voucher_lifecycle.rs
├── output.txt
├── README.md
├── src
│   ├── examples
│   ├── lib.rs
│   ├── main.rs
│   ├── models
│   │   ├── mod.rs
│   │   ├── readme_de.md
│   │   ├── voucher.rs
│   │   └── voucher_standard_definition.rs
│   ├── services
│   │   ├── crypto_utils.rs
│   │   ├── mod.rs
│   │   ├── utils.rs
│   │   ├── voucher_manager.rs
│   │   └── voucher_validation.rs
│   └── utilities
├── tests
│   ├── test_crypto_utils.rs
│   ├── test_utils.rs
│   └── test_voucher_lifecycle.rs
├── todo.md
└── voucher_standards
    ├── minuto_standard.toml
    ├── silver_standard.toml
    └── standard_template.toml
```

## 7. Implementierte Kernfunktionen
Basierend auf den bereitgestellten Dateien (`utils.rs`, `crypto_utils.rs`):

### `services::utils` Modul
Dieses Modul enthält Hilfsfunktionen für Zeitstempel.

- `pub fn get_timestamp(years_to_add: i32, end_of_year: bool) -> String`
  - Gibt den aktuellen Zeitstempel im ISO 8601-Format (UTC) mit Mikrosekundenpräzision zurück.
  - Optional können Jahre hinzugefügt werden.
  - Wenn `end_of_year` auf `true` gesetzt ist, wird die Zeit auf den letzten Moment des entsprechenden Jahres gesetzt.

- `pub fn get_current_timestamp() -> String`
  - Eine Komfortfunktion, die den aktuellen Zeitstempel im ISO 8601-Format (UTC) zurückgibt (ruft `get_timestamp(0, false)` auf).

### `services::crypto_utils` Modul
Dieses Modul enthält kryptographische Hilfsfunktionen für Schlüsselgenerierung, Hashing, Signaturen und User ID-Verwaltung.

- `pub fn generate_mnemonic(word_count: usize, language: Language) -> Result<String, Box<dyn std::error::Error>>`
  - Generiert eine mnemonische Phrase mit einer bestimmten Wortanzahl und Sprache.

- `pub fn get_hash(input: impl AsRef<[u8]>) -> String`
  - Berechnet einen SHA3-256-Hash der Eingabe und gibt ihn als Base58-kodierten String zurück.

- `pub fn derive_ed25519_keypair(mnemonic_phrase: &str, passphrase: Option<&str>) -> (EdPublicKey, SigningKey)`
  - Leitet ein Ed25519-Schlüsselpaar aus einer mnemonischen Phrase und einem optionalen Passphrase ab.

- `pub fn generate_ed25519_keypair_for_tests(seed: Option<&str>) -> (EdPublicKey, SigningKey)`

  - **Nur für Tests:** Erzeugt ein zufälliges oder (mit Seed) deterministisches Ed25519-Schlüsselpaar.

- `pub fn ed25519_pub_to_x25519(ed_pub: &EdPublicKey) -> X25519PublicKey`
  - Konvertiert einen Ed25519 Public Key in einen X25519 Public Key für den Diffie-Hellman-Schlüsselaustausch.

- `pub fn generate_ephemeral_x25519_keypair() -> (X25519PublicKey, EphemeralSecret)`
  - Generiert ein temporäres X25519-Schlüsselpaar für Diffie-Hellman (Forward Secrecy).

- `pub fn perform_diffie_hellman(our_secret: EphemeralSecret, their_public: &X25519PublicKey) -> [u8; 32]`
  - Führt den Diffie-Hellman-Schlüsselaustausch durch.

- `pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Signature`
  - Signiert eine Nachricht mit einem Ed25519 Signing Key.

- `pub fn verify_ed25519(public_key: &EdPublicKey, message: &[u8], signature: &Signature) -> bool`

  - Verifiziert eine Ed25519-Signatur.

- `pub enum UserIdError`

  - Fehlertypen für die User ID-Erstellung.
- `pub fn create_user_id(public_key: &EdPublicKey, user_prefix: Option<&str>) -> Result<String, UserIdError>`
  - Generiert eine User ID aus dem Public Key mit einem optionalen Präfix, Prüfsumme und Präfixlängenindikator.

- `pub fn validate_user_id(user_id: &str) -> bool`
  - Validiert eine User ID-Zeichenkette.

- `pub enum GetPubkeyError`
  - Fehlertypen für die Funktion `get_pubkey_from_user_id`.

- `pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, GetPubkeyError>`
  - Extrahiert den Ed25519 Public Key aus einer User ID-Zeichenkette.

### `services::voucher_manager` Modul
Dieses Modul stellt die Kernlogik für die Erstellung und Verarbeitung von Gutscheinen bereit.

- `pub fn create_voucher(data: NewVoucherData, standard_definition: &VoucherStandardDefinition, creator_signing_key: &SigningKey) -> Result<Voucher, VoucherManagerError>`
  - Orchestriert die Erstellung eines neuen, vollständigen Gutscheins.
  - Übernimmt Werte aus der `VoucherStandardDefinition` (z.B. Nennwert-Einheit, Gültigkeits-Rundungsregeln).
  - Prüft die Gültigkeitsdauer gegen die Mindestanforderungen des Standards.
  - Erzeugt die `voucher_id` aus dem Hash des initialen Zustands.
  - Signiert den initialen Zustand mit dem Schlüssel des Erstellers.
  - Erstellt und signiert die kryptographisch verkettete `init`-Transaktion.

- `pub fn create_split_transaction(voucher: &Voucher, standard: &VoucherStandardDefinition, sender_id: &str, sender_key: &SigningKey, recipient_id: &str, amount_to_send_str: &str) -> Result<Voucher, VoucherManagerError>`

  - Erstellt eine Kopie des Gutscheins mit einer neuen, angehängten `split`-Transaktion.
  - Prüft, ob der Gutschein teilbar ist.
  - Verwendet `get_spendable_balance` zur Guthabenprüfung.
  - Berechnet den `prev_hash` aus der letzten Transaktion, um die Kette fortzusetzen.
  - Erzeugt und signiert die neue Transaktion.

- `pub fn to_json(voucher: &Voucher) -> Result<String, VoucherManagerError>`

  - Serialisiert ein `Voucher`-Struct in einen formatierten JSON-String.

- `pub fn from_json(json_str: &str) -> Result<Voucher, VoucherManagerError>`
  - Deserialisiert einen JSON-String in ein `Voucher`-Struct.

- `pub fn load_standard_definition(toml_str: &str) -> Result<VoucherStandardDefinition, VoucherManagerError>`
  - Deserialisiert einen TOML-String in ein `VoucherStandardDefinition`-Struct, um Regelwerke zu laden.

### `services::voucher_validation` Modul
Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts gegen die Regeln seines Standards.

- `pub fn validate_voucher_against_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), ValidationError>`
  - Führt eine umfassende Prüfung des Gutscheins durch, inklusive:
  - **Konsistenz:** Überprüfung erforderlicher Felder, Abgleich von festen Werten (Nennwert-Einheit, Teilbarkeit) mit dem Standard.
  - **Gültigkeit:** Verifiziert, dass die Gültigkeitsdauer des Gutscheins den Mindestanforderungen des Standards entspricht.
  - **Ersteller-Signatur:** Verifiziert die Signatur des Erstellers über dem initialen Zustand des Gutscheins.
  - **Bürgen-Signaturen:** Validiert die Anzahl und die kryptographische Gültigkeit jeder einzelnen Bürgen-Signatur (inkl. `signature_id` und digitaler Signatur). Prüft bei Bedarf geschlechtsspezifische Regeln.
  - **Transaktionskette:** Validiert die gesamte Kette von Transaktionen durch Überprüfung der `prev_hash`-Verkettung, der Integrität jeder `t_id`, der Signatur jedes Senders und der Geschäftslogik (z.B. ausreichende Deckung, korrekte Summen bei Splits).

- `pub fn get_spendable_balance(voucher: &Voucher, user_id: &str, standard: &VoucherStandardDefinition) -> Result<Decimal, ValidationError>`

  - Berechnet das aktuell verfügbare Guthaben für einen Nutzer, indem es den Zustand nach der letzten Transaktion im Gutschein analysiert.

### Beispiel-Playgrounds
Die Dateien `playground_utils.rs` und `playground_crypto_utils.rs` demonstrieren die Nutzung von Hilfsfunktionen. Die Datei `playground_voucher_lifecycle.rs` ist ein umfassendes Beispiel, das den gesamten Lebenszyklus eines Gutscheins zeigt: Erstellung (mit Fehlerfall bei falscher Gültigkeit), Hinzufügen von Bürgen, Validierung, eine Split-Transaktion und die Simulation eines kryptographisch nachweisbaren Double-Spend-Betrugs. Diese Dateien sind nicht Teil der `voucher_core` API.