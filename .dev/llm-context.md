# llm-context.md für decentral-voucher-system-core

Dies ist die Kontextdatei für die Entwicklung der Rust-Core-Bibliothek `voucher_core`. Sie dient als "README für die KI", um ein umfassendes Verständnis des Projekts und seiner Anforderungen zu gewährleisten.

## 1\. Projekt & Zweck

- **Projektname:** `voucher_core`

- **Zweck:** Implementierung der Kernlogik eines dezentralen, vertrauensbasierten elektronischen Gutschein-Zahlungssystems.

- **Hauptziel:** Bereitstellung einer robusten, sicheren und performanten Bibliothek, die später über FFI (Foreign Function Interface) und WASM (WebAssembly) in anderen Umgebungen (z.B. Desktop-Anwendungen, Web-Clients) genutzt werden kann.

- **Kernfunktionalität:** Erstellung, Verwaltung und Verifizierung von digitalen Gutscheinen und deren Transaktionshistorie.

## 2\. Tech-Stack

- **Sprache:** Rust

- **Zielplattformen:** FFI-kompatibel (für Bindings zu anderen Sprachen) und WASM-kompatibel (für Web-Anwendungen).

- **Kryptographie:** Standard-Rust-Kryptographie-Bibliotheken für digitale Signaturen und Hashing.

## 3\. Architektur & Designprinzipien

- **Modulare Architektur:** Die Bibliothek ist in logische Module unterteilt. Die Architektur trennt klar die Geschäftslogik (in einer `Wallet`-Fassade) von der Persistenz (hinter einem `Storage`-Trait), um Flexibilität und Testbarkeit zu maximieren.

- **Dezentraler Ansatz:** Das System basiert auf dezentralen Gutscheinen (Textdateien), die eine verkettete Liste der Transaktionshistorie enthalten (eine Art "Mini-Blockchain pro Gutschein").

- **Kein globales Ledger:** Im Gegensatz zu traditionellen Blockchains wird bewusst auf ein globales, verteiltes Ledger verzichtet. Die Integrität wird durch digitale Signaturen und soziale Kontrolle gewährleistet.

- **Offline-Fähigkeit:** Transaktionen sollen auch offline durchgeführt werden können, indem die aktualisierte Gutschein-Datei direkt an den neuen Halter übergeben wird.

- **Fokus auf Betrugserkennung, nicht -vermeidung:** Da es kein globales Ledger gibt, kann die Core-Bibliothek nicht verhindern, dass ein Nutzer widersprüchliche Transaktionshistorien (Double Spending) erzeugt. Das System stellt stattdessen sicher, dass jeder Betrugsversuch durch digitale Signaturen kryptographisch beweisbar ist, was eine Erkennung und soziale Sanktionen in einem übergeordneten System (Layer 2) ermöglicht.

- **Fokus auf Kernlogik:** Zunächst wird nur die grundlegende Funktionalität der Gutschein- und Transaktionsverwaltung implementiert. Die "Transaction Verification Layer" und "User Trust Verification Layer" (Layer 2 mit Servern) sollen *nicht* implementiert werden, aber die Struktur der Transaktionsketten sollte so optimiert werden, dass eine spätere Erweiterung um diese Layer möglich ist.

- **FFI/WASM-Kompatibilität:** Rust-Typen und -Funktionen müssen so gestaltet sein, dass sie einfach über FFI und WASM exponiert werden können (z.B. durch Verwendung von `#[no_mangle]`, C-kompatiblen Datentypen und `wasm_bindgen`).

## 4\. Coding-Standards & Wichtige Regeln

- **Rust Best Practices:** Einhaltung der idiomatischen Rust-Programmierung, Fokus auf Sicherheit, Performance und Speichereffizienz.

- **Fehlerbehandlung:** Robuste Fehlerbehandlung mit Rusts `Result`-Typ.

- **Dokumentation:** Umfassende interne Dokumentation (Doc-Kommentare) für alle öffentlichen Funktionen und Strukturen.

- **Testen:** Umfassende Unit- und Integrationstests.

- **Keine externen Netzwerkaufrufe:** Die Core-Bibliothek soll keine direkten Netzwerkaufrufe für die Layer-2-Funktionalität enthalten. Diese Interaktionen werden von den übergeordneten Anwendungen gehandhabt, die `voucher_core` nutzen.

## 5\. Kernkonzepte aus dem Paper (Zusammenfassung)

Gutschein-Struktur: Das universelle Gutschein-Container-Format

Ein Gutschein ist im Wesentlichen eine Textdatei (repräsentiert als JSON), die alle möglichen Informationen enthält, die ein Gutschein jemals haben könnte. Jede einzelne Gutscheininstitution wird in diesem einheitlichen JSON-Schema abgebildet. Die spezifischen Regeln und Eigenschaften eines Gutscheintyps (wie "Minuto-Gutschein" oder "Silber-Umlauf-Gutschein") werden in separaten Standard-Definitionen (voucher\_standard\_definitions) festgelegt.

Diese Definitionen werden als externe **TOML-Dateien** (z.B. aus einem `voucher_standards/`-Verzeichnis) bereitgestellt und zur Laufzeit geparst. Die TOML-Struktur ist klar in drei Blocker unterteilt:

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
      "t_type": "STRING",               // Art der Transaktion: "init" für Initialisierung, "split" für Teilung. Bei einem vollen Transfer wird das Feld weggelassen.
      "t_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Zeitpunkt der Transaktion.
      "sender_id": "STRING",            // ID des Senders der Transaktion.
      "recipient_id": "STRING",         // ID des Empfängers der Transaktion.
      "amount": "STRING",               // Der Betrag, der bei dieser Transaktion bewegt wurde.
      "sender_remaining_amount": "STRING",// Der Restbetrag beim Sender. Dieses Feld existiert nur bei "split"-Transaktionen.
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

### Double-Spending-Erkennung

Ein **Double Spend** liegt vor, wenn ein Nutzer von einem bestimmten Zustand des Gutscheins (repräsentiert durch den `prev_hash` der letzten gültigen Transaktion) zwei oder mehr unterschiedliche neue Transaktionen erstellt und diese an verschiedene Personen verteilt.

#### Anonymisierte Erkennung auf Layer 2

Die Transaktionsstruktur ist für eine **anonymisierte Betrugserkennung** durch ein übergeordnetes System (Layer 2) optimiert:

- **Anonymer Fingerabdruck:** Anstatt `prev_hash` und `sender_id` direkt preiszugeben, erzeugt ein Client einen anonymen "Fingerabdruck": `prvhash_senderid_hash = hash(prev_hash + sender_id)`.

- **Server-Upload:** Der Client lädt nur diesen Fingerabdruck zusammen mit der `t_id`, der `sender_signature` und dem `t_time` der Transaktion hoch. Der Server kann daraus weder Absender noch Gutschein-Herkunft ableiten.

- **Aufdeckung & Beweis:** Ein Double Spend wird erkannt, wenn der Server für einen bekannten `prvhash_senderid_hash` einen neuen Eintrag mit einer anderen `t_id` erhält. Der Server kann dem zweiten Einreicher die Daten des ersten Eintrags als Beweis zurücksenden. Der Client hat dann zwei unterschiedliche, aber beide gültig vom selben Absender signierte Transaktionen, die vom selben `prev_hash` ausgehen. Der Betrug ist bewiesen, und der Zeitstempel `t_time` hilft bei der Entscheidung, welche Transaktion die ursprüngliche war.

#### Erkennung ohne Layer-2-Server (durch Pfad-Vereinigung)

Ein Double Spend kann auch ohne einen zentralen Server erkannt werden, wenn sich die aufgespaltenen Transaktionspfade bei einem späteren Nutzer wieder treffen. Da Gutscheine im System zirkulieren und oft beim Ersteller wieder eingelöst werden, ist dies ein praxisnaher Anwendungsfall.

- **Mechanismus:** Ein Nutzer, der einen Gutschein erhält, kann dessen Transaktionshistorie mit den Historien von bereits erhaltenen oder archivierten Gutscheinen vergleichen.

- **Beispiel:** Der ursprüngliche Ersteller eines Gutscheins erhält später zwei unterschiedliche Gutschein-Dateien zur Einlösung zurück. Beide leiten ihre Herkunft von seinem ursprünglichen Gutschein ab. Beim Vergleich der Historien stellt er fest, dass beide Dateien eine unterschiedliche Transaktion enthalten, die aber vom selben `prev_hash` abstammt. Damit ist der Double Spend bewiesen.

- **Voraussetzung:** Diese Methode erfordert, dass Nutzer (insbesondere Akteure wie Ersteller, die Einlösungen akzeptieren) alte Gutschein-Zustände vorhalten, um eine Vergleichsbasis zu haben.

### Weitere relevante Konzepte (für zukünftige Erweiterungen optimieren)

- **Teilzahlungen:** Ein Gutschein kann in kleinere Beträge aufgeteilt werden. Der Restbetrag verbleibt beim Sender, der daraus weitere Transaktionen erstellen kann.

- **Zusätzliche Signaturen:** Möglichkeit, weitere Signaturen (z.B. von Bürgen/Garanten) in die Gutschein-Datei zu integrieren.

- **Verschlüsselung:** Die Übertragung von Daten (z.B. Transaktionsbündel) wird durch einen generischen `SecureContainer` geschützt, der Multi-Empfänger-Fähigkeiten mittels statischem Diffie-Hellman (X25519) und Key-Wrapping bietet.

- **Begrenzte Gültigkeitsdauer:** Gutscheine sollen nach einer bestimmten Zeit ihre Gültigkeit verlieren.

- **Keine Layer 2 Implementierung:** Die Logik für die "Transaction Verification Layer" (Server-basiertes Double-Spending-Matching) und die "User Trust Verification Layer" (Reputationsmanagement) wird in dieser Core-Bibliothek *nicht* implementiert. Die Datenstrukturen für Transaktionsketten sollen jedoch eine spätere Anbindung an solche Systeme ermöglichen.

## 6\. Aktueller Projektstrukturbaum

```
.
├── Cargo.lock
├── Cargo.toml
├── examples
│   ├── playground_crypto_utils.rs
│   ├── playground_utils.rs
│   └── playground_voucher_lifecycle.rs
├── output.txt
├── README.md
├── src
│   ├── archive
│   │   ├── file_archive.rs
│   │   └── mod.rs
│   ├── error.rs
│   ├── examples
│   ├── lib.rs
│   ├── main.rs
│   ├── models
│   │   ├── conflict.rs
│   │   ├── mod.rs
│   │   ├── profile.rs
│   │   ├── readme_de.md
│   │   ├── secure_container.rs
│   │   ├── voucher.rs
│   │   └── voucher_standard_definition.rs
│   ├── services
│   │   ├── bundle_processor.rs
│   │   ├── conflict_manager.rs
│   │   ├── crypto_utils.rs
│   │   ├── mod.rs
│   │   ├── secure_container_manager.rs
│   │   ├── utils.rs
│   │   ├── voucher_manager.rs
│   │   └── voucher_validation.rs
│   ├── storage
│   │   ├── file_storage.rs
│   │   └── mod.rs
│   ├── utilities
│   └── wallet.rs
├── tests
│   ├── test_archive.rs
│   ├── test_crypto_utils.rs
│   ├── test_file_storage.rs
│   ├── test_local_double_spend_detection.rs
│   ├── test_local_instance_id.rs
│   ├── test_secure_container.rs
│   ├── test_security_vulnerabilities.rs
│   ├── test_utils.rs
│   └── test_voucher_lifecycle.rs
├── todo.md
└── voucher_standards
    ├── minuto_standard.toml
    ├── silver_standard.toml
    └── standard_template.toml
```

## 7\. Implementierte Kernfunktionen

Basierend auf den bereitgestellten Dateien:

### `src/wallet.rs` Modul

Definiert die `Wallet`-Fassade, die die zentrale, öffentliche Schnittstelle der Bibliothek darstellt. Sie kapselt den In-Memory-Zustand des Nutzers und **orchestriert** alle Operationen durch Aufrufe an spezialisierte Service-Module.

- `pub struct Wallet`

  - Hält `UserProfile`, `VoucherStore`, `BundleMetadataStore`, `FingerprintStore` und `ProofStore` als In-Memory-Zustand.

- `pub fn new_from_mnemonic(mnemonic_phrase: &str, user_prefix: Option<&str>) -> Result<(Self, UserIdentity), VoucherCoreError>`

  - Erstellt ein brandneues, leeres Wallet und die dazugehörige `UserIdentity` (mit privatem Schlüssel) aus einer Mnemonic-Phrase.

- `pub fn load<S: Storage>(storage: &S, auth: &AuthMethod, identity: UserIdentity) -> Result<Self, VoucherCoreError>`

  - Lädt ein existierendes Wallet aus einer `Storage`-Implementierung.

- `pub fn save<S: Storage>(&self, storage: &mut S, identity: &UserIdentity, password: &str) -> Result<(), StorageError>`

  - Speichert den aktuellen Zustand aller Datenspeicher des Wallets.

- `pub fn reset_password<S: Storage>(storage: &mut S, identity: &UserIdentity, new_password: &str) -> Result<(), StorageError>`

  - Eine Wrapper-Funktion, die die Passwort-Zurücksetzung im `Storage`-Layer aufruft.

- `pub fn create_transfer(...) -> Result<(Vec<u8>, Voucher), VoucherCoreError>`

  - Die zentrale, sichere Methode zum Senden von Gutscheinen.

  - Führt eine **proaktive Double-Spend-Prüfung** durch.

  - Delegiert die Erstellung der Transaktion an den `voucher_manager`.

  - Verwaltet den Wallet-Zustand (archiviert die alte Instanz, erstellt ggf. eine neue für den Restbetrag).

  - Delegiert die Erstellung des `SecureContainer` an den `bundle_processor`.

- `pub fn process_encrypted_transaction_bundle(...) -> Result<ProcessBundleResult, VoucherCoreError>`

  - Kapselt die Geschäftslogik zum Empfangen von Gutscheinen.

  - Delegiert das Öffnen des `SecureContainer` an den `bundle_processor`.

  - Fügt die empfangenen Gutscheine dem Wallet hinzu.

  - Führt eine **reaktive Double-Spend-Prüfung** durch Aufruf des `conflict_manager` durch.

### `src/storage` Modul (`mod.rs`, `file_storage.rs`)

Definiert die Abstraktion für die persistente Speicherung und stellt eine Standardimplementierung für das Dateisystem bereit.

- `pub trait Storage`

  - Definiert die Schnittstelle für Speicheroperationen, die nun für jeden Datenspeicher separat existieren (`load/save_wallet`, `load/save_bundle_metadata`, `load/save_fingerprints`, `load/save_proofs`).

- `pub struct FileStorage`

  - Implementiert den `Storage`-Trait.

  - Verwaltet die Ver- und Entschlüsselung der Wallet-Daten in mehreren separaten Dateien (`profile.enc`, `vouchers.enc`, `bundles.meta.enc`, `fingerprints.enc`, `proofs.enc`).

  - Implementiert die "Zwei-Schloss"-Mechanik mit Key-Wrapping für den Passwort-Zugriff und die Mnemonic-Wiederherstellung.

### `src/archive` Modul (`mod.rs`, `file_archive.rs`)

Definiert die Abstraktion für ein persistentes Archiv von Gutschein-Zuständen.

- `pub trait VoucherArchive`

  - Definiert die Schnittstelle für ein Archiv, das dazu dient, *jeden jemals gesehenen* Zustand eines Gutscheins zu speichern (forensische Analyse), im Gegensatz zum `Storage`-Trait, der den *aktuellen* Wallet-Zustand verwaltet.

- `pub struct FileVoucherArchive`

  - Eine Implementierung, die jeden archivierten Gutschein als separate JSON-Datei speichert.

### `services::utils` Modul

Dieses Modul enthält Hilfsfunktionen für Zeitstempel.

- `pub fn get_timestamp(years_to_add: i32, end_of_year: bool) -> String`

  - Gibt den aktuellen Zeitstempel im ISO 8601-Format (UTC) mit Mikrosekundenpräzision zurück.

- `pub fn get_current_timestamp() -> String`

  - Eine Komfortfunktion, die den aktuellen Zeitstempel im ISO 8601-Format (UTC) zurückgibt.

### `services::crypto_utils` Modul

Dieses Modul enthält kryptographische Hilfsfunktionen für Schlüsselgenerierung, Hashing, Signaturen und User ID-Verwaltung.

- `pub fn get_hash(input: impl AsRef<[u8]>) -> String`

  - Berechnet einen SHA3-256-Hash der Eingabe und gibt ihn als Base58-kodierten String zurück.

- `pub fn derive_ed25519_keypair(mnemonic_phrase: &str, passphrase: Option<&str>) -> (EdPublicKey, SigningKey)`

  - Leitet ein Ed25519-Schlüsselpaar aus einer mnemonischen Phrase ab.

- `pub fn create_user_id(public_key: &EdPublicKey, user_prefix: Option<&str>) -> Result<String, UserIdError>`

  - Generiert eine User ID aus dem Public Key mit einem optionalen Präfix.

- `pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, GetPubkeyError>`

  - Extrahiert den Ed25519 Public Key aus einer User ID-Zeichenkette.

### `services::voucher_manager` Modul

Dieses Modul stellt die Kernlogik für die Erstellung und Verarbeitung von Gutscheinen bereit.

- `pub fn create_voucher(data: NewVoucherData, standard_definition: &VoucherStandardDefinition, creator_signing_key: &SigningKey) -> Result<Voucher, VoucherManagerError>`

  - Orchestriert die Erstellung eines neuen, vollständigen Gutscheins.

- `pub fn create_transaction(voucher: &Voucher, standard: &VoucherStandardDefinition, sender_id: &str, sender_key: &SigningKey, recipient_id: &str, amount_to_send_str: &str) -> Result<Voucher, VoucherCoreError>`

  - Erstellt eine Kopie des Gutscheins mit einer neuen Transaktion.

### `services::voucher_validation` Modul

Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts gegen die Regeln seines Standards.

- `pub fn validate_voucher_against_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), ValidationError>`

  - Führt eine umfassende Prüfung des Gutscheins durch.

- `pub fn get_spendable_balance(voucher: &Voucher, user_id: &str, standard: &VoucherStandardDefinition) -> Result<Decimal, ValidationError>`

  - Berechnet das aktuell verfügbare Guthaben für einen Nutzer.

### `services::secure_container_manager.rs` Modul

Dieses Modul implementiert die Kernlogik für den `SecureContainer`.

- `pub fn create_secure_container(...) -> Result<SecureContainer, VoucherCoreError>`

  - Erstellt, verschlüsselt und signiert einen `SecureContainer` für einen oder mehrere Empfänger.

- `pub fn open_secure_container(...) -> Result<(Vec<u8>, PayloadType), VoucherCoreError>`

  - Verifiziert und entschlüsselt einen `SecureContainer` für einen berechtigten Empfänger.

### `services::bundle_processor.rs` Modul

Dieses Modul kapselt die Logik für die Verarbeitung von `TransactionBundle`-Objekten.

- `pub fn create_and_encrypt_bundle(...) -> Result<(Vec<u8>, TransactionBundle), VoucherCoreError>`

  - Erstellt ein `TransactionBundle`, signiert es und verpackt es in einen `SecureContainer`.

- `pub fn open_and_verify_bundle(...) -> Result<TransactionBundle, VoucherCoreError>`

  - Öffnet einen `SecureContainer`, extrahiert das `TransactionBundle` und verifiziert dessen Signatur.

### `services::conflict_manager.rs` Modul

Dieses Modul kapselt die gesamte Geschäftslogik zur Erkennung und Verwaltung von Double-Spending-Konflikten.

- `pub fn scan_and_update_own_fingerprints(...) -> Result<(), VoucherCoreError>`

  - Durchsucht die Gutscheine eines Wallets und aktualisiert dessen Fingerprint-Speicher.

- `pub fn check_for_double_spend(...) -> DoubleSpendCheckResult`

  - Vergleicht eigene und fremde Fingerprints, um Konflikte zu finden.

- `pub fn verify_conflict_and_create_proof(...) -> Result<Option<ProofOfDoubleSpend>, VoucherCoreError>`

  - Führt die kryptographische Verifizierung eines Konflikts durch und erstellt einen fälschungssicheren Beweis.

- `pub fn import_foreign_fingerprints(...) -> Result<usize, VoucherCoreError>`

  - Importiert Fingerprints von anderen Peers.

### `src/error.rs` Modul

Dieses Modul definiert den zentralen, einheitlichen Fehlertyp für die Bibliothek.

- `pub enum VoucherCoreError`

  - Ein `thiserror`-basiertes Enum, das alle spezifischen Fehler aus den verschiedenen Modulen bündelt.

### `src/models` Module

Diese Module definieren die zentralen Datenstrukturen der Bibliothek.

- **`profile.rs`:** Definiert die Strukturen des Nutzer-Wallets (`UserIdentity`, `VoucherStore`, `BundleMetadataStore` etc.) und den `VoucherStatus`-Enum.
- **`conflict.rs`:** Definiert die Strukturen für die Double-Spend-Erkennung (`TransactionFingerprint`, `FingerprintStore`, `ProofOfDoubleSpend`).
- **`secure_container.rs`:** Definiert den generischen, verschlüsselten `SecureContainer`.
- **`voucher.rs`:** Definiert die Kernstruktur eines `Voucher`-Objekts mit all seinen Feldern.
- **`voucher_standard_definition.rs`:** Definiert die Struktur für das Parsen der TOML-basierten Regelwerke.

### Beispiel-Playgrounds

Die Dateien `playground_utils.rs` und `playground_crypto_utils.rs` demonstrieren die Nutzung von Hilfsfunktionen. Die Datei `playground_voucher_lifecycle.rs` ist ein umfassendes Beispiel, das den gesamten Lebenszyklus eines Gutscheins zeigt: Erstellung (mit Fehlerfall bei falscher Gültigkeit), Hinzufügen von Bürgen, Validierung, eine Split-Transaktion und die Simulation eines kryptographisch nachweisbaren Double-Spend-Betrugs. Diese Dateien sind nicht Teil der `voucher_core` API.