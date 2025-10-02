.dev/design_decisions.md

**Abbildung des Geschlechts im `Creator` Struct:**
    * **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `Int definiert. eschlecht des Erstellers ISO 5218 (1 = male", 2 = female", 0 = not known, 9 = Not applicable)
    * **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken, die vorwiegend in westlichen Ländern verbreitet sind. Sie bietet eine einfache und ausreichende Abbildung für die Zwecke der Core-Bibliothek (z.B. für Bürgen-Anforderungen des Minuto-Standards) und überlässt komplexere oder sensiblere Abbildungen den höheren Anwendungsschichten, die `voucher_core` nutzen.
---
** Für Gutschein Standard wird toml verwendet **
    * damit lassen sich kommentare nutzen damit der standart auch besser lesbar wird. Bei Json keine Kommentare möglich.
---
## Notwendigkeit und Berechnung der `local_voucher_instance_id`
### Warum wird eine `local_voucher_instance_id` benötigt?
Eine `local_voucher_instance_id` ist zwingend erforderlich, um **Gutschein-Instanzen eindeutig zu verwalten**, nachdem eine **`split`-Transaktion** stattgefunden hat.
- **Problem:** Eine `split`-Transaktion erzeugt aus einem Ursprungsgutschein mehrere neue, separat spendable Guthaben (z.B. einen Teil für einen Empfänger und den Restbetrag für den Sender). Alle diese Instanzen teilen sich jedoch weiterhin dieselbe globale `voucher_id`.
- **Lösung:** Da die `voucher_id` allein nicht mehr eindeutig ist, dient die `local_voucher_instance_id` als **stabiler und einzigartiger Primärschlüssel** für jede dieser Instanzen innerhalb der lokalen Wallet-Verwaltung (z.B. in einer `HashMap` oder Datenbank).

# todo Berechnung hat sich vereinfach und muss nicht so komplex sein. (Berschreibung anpassen)
### Warum ist die Berechnung scheinbar komplex?
Die Berechnung ist nicht willkürlich komplex, sondern präzise darauf ausgelegt, einen kritischen Anwendungsfall robust zu handhaben: die **lokale Double-Spending-Erkennung**.
Die Komplexität entsteht, weil die Logik zwischen zwei Zuständen eines Gutscheins im Profil des Nutzers unterscheiden muss:
1.  **Aktiver (spendabler) Gutschein:** Der Nutzer besitzt ein Guthaben `> 0`. Die ID muss diesen aktuellsten, besessenen Zustand widerspiegeln.
2.  **Archivierter (ausgegebener) Gutschein:** Der Nutzer hat das gesamte Guthaben ausgegeben (Guthaben `= 0`). Der Gutschein wird aber als "leere Hülle" für die Transaktionshistorie aufbewahrt. Seine ID muss auf dem **letzten Zustand eingefroren werden, in dem er aktiv war**.
Um dies zu erreichen, kann die Berechnung nicht einfach die letzte Transaktion des Gutscheins nehmen. Stattdessen muss sie die Transaktionshistorie **rückwärts durchsuchen**, um den letzten Zeitpunkt zu finden, an dem der Profilinhaber tatsächlich ein Guthaben besaß. Dieser gezielte Suchvorgang macht die Berechnung scheinbar komplex, ist aber die Grundlage für eine konsistente und sichere Zustandsverwaltung.


# Architekturentscheidung: Identitäts- und Schlüsselmanagement in voucher_core
Zur Verwaltung von Benutzerkonten auf mehreren Geräten (z.B. PC und Handy) wurden zwei primäre Architekturmodelle evaluiert. Nach sorgfältiger Abwägung der Sicherheits- und Benutzerfreundlichkeits-Aspekte haben wir uns für Modell B entschieden, da es eine inhärent sicherere und robustere Lösung darstellt.

## Die evaluierten Modelle
### Modell A: Ein einziger kryptographischer Schlüssel mit Präfix-Aliasen
Konzept: Der Nutzer besitzt eine einzige kryptographische Identität (z.B. did:key:z...A). Verschiedene Geräte verwenden lediglich unterschiedliche "Adressen" oder Aliase, wie `pc-chk@did:key:z...A` und `handy-chk@did:key:z...A`.

Implikation: Beide Adressen verweisen auf dasselbe Schlüsselpaar. Ein an handy@... gesendeter Gutschein könnte prinzipiell auch von der PC-Wallet verarbeitet werden. Dies erfordert eine komplexe Synchronisierungs- und "Claiming"-Logik, um unbeabsichtigte Double Spends zu verhindern.

### Modell B: Kryptographisch getrennte Schlüssel pro Konto/Gerät (Entschiedenes Modell)
Konzept: Jedes Konto, das ein Nutzer anlegt (z.B. für "PC" oder "Handy"), ist eine eigenständige kryptographische Identität mit einem eigenen, einzigartigen Schlüsselpaar. Die Adressen lauten z.B. `pc-chkB@did:key:z...B` und `handy-chkC@did:key:z...C`.

Implikation: Ein an `pc-chkB@did:key:z...B` gesendeter Gutschein kann ausschließlich von der Wallet verarbeitet werden, die den privaten Schlüssel für `...B` besitzt. Eine Annahme durch die "Handy"-Wallet ist kryptographisch unmöglich.

## Begründung der Entscheidung für Modell B
Die Entscheidung für Modell B basiert auf drei fundamentalen Vorteilen gegenüber Modell A:

Maximale Sicherheit durch Eliminierung von Protokoll-Fehlern
Das Hauptproblem von Modell A ist, dass es eine gefährliche Fehlerklasse zulässt: Ein Nutzer kann denselben eingehenden Gutschein versehentlich auf zwei Geräten annehmen und erzeugt so unwissentlich einen Double Spend. Diesen Fehler nachträglich zu entdecken, erfordert ständige, disziplinierte Synchronisierung. Modell B eliminiert diese Fehlerquelle auf der Protokollebene. Ein unbeabsichtigter Double Spend durch fehlerhafte Annahme ist unter Modell B technisch unmöglich, was das System inhärent sicherer macht.

Vereinfachung der Core-Bibliothek und des Protokolls
Modell A erfordert komplexe Zusatzlogik in voucher_core, um die Synchronisationsprobleme zu bewältigen (z.B. "Claiming"-Transaktionen, Konflikterkennung, "Earliest-Wins"-Heuristik). Modell B hingegen vereinfacht das Protokoll drastisch. Die Validierung eines Transfers ist ein simpler, zustandsloser Check: "Stimmt der Empfänger-Schlüssel mit meinem Schlüssel überein?". Ein einfacheres Protokoll ist robuster, leichter zu prüfen und weniger anfällig für Implementierungsfehler.

Schaffung eines klaren mentalen Modells für den Nutzer
Modell B erzwingt ein klares und leicht verständliches mentales Modell: "Ein Konto, ein Gerät, ein Guthaben." Der Nutzer versteht intuitiv, dass seine Guthaben getrennt sind. Er muss nicht über den verborgenen Zustand anderer Geräte nachdenken. Es ersetzt den fehleranfälligen Zwang zur Synchronisierung durch die einfache und verständliche Aktion eines normalen Transfers, wenn Guthaben zwischen Geräten bewegt werden soll.

Pragmatische Umsetzung: Nutzerkomfort durch deterministische Ableitung
Um den Nachteil der Verwaltung mehrerer Geheimnisse zu umgehen, wird Modell B nutzerfreundlich umgesetzt:

Einziger Mnemonic: Der Nutzer muss sich nur einen einzigen Mnemonic (Seed-Phrase) merken.

Präfix als Ableitungs-Parameter: Bei der Erstellung eines neuen Kontos wählt der Nutzer einen Namen (das "Präfix", z.B. "pc"). Dieser Name wird als Suffix an die optionale BIP-39-Passphrase angehängt.

final_passphrase = optionale_user_passphrase + "pc"

* **Sicheres und lesbares ID-Format:** Um Tippfehler zu verhindern und die Integrität der ID sicherzustellen, wird eine kurze Prüfsumme (`checksum`) generiert. Sie verbindet den menschenlesbaren Präfix kryptographisch mit dem `did:key`. Das finale Format lautet: `[präfix-]prüfsumme@did:key`.
    * **Mit Präfix:** `pc-aB3@did:key:z...B`
    * **Ohne Präfix (Standardkonto):** `aB3@did:key:z...A`


Sicherheit: Dieser Ansatz ist kryptographisch sicher. Aufgrund des "Avalanche-Effekts" der Key-Derivation-Functions erzeugt jede noch so kleine Änderung an der Passphrase ein völlig anderes, unkorreliertes Schlüsselpaar.

Diese Methode kombiniert das Beste aus beiden Welten: den Komfort eines einzigen Geheimnisses für den Nutzer mit der maximalen Sicherheit kryptographisch getrennter Konten.