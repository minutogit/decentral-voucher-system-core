# Design-Entscheidung: `is_divisible` vs. "split"-Transaktion

Dieses Dokument erklärt die bewusste Design-Entscheidung, warum in den Gutschein-Standards sowohl die Eigenschaft `is_divisible` als auch der Transaktionstyp `"split"` existieren und warum sie nicht redundant, sondern für ein robustes System notwendig sind.

## Die zwei Konzepte

Auf den ersten Blick könnte man annehmen, dass die beiden Felder denselben Zweck erfüllen. Sie operieren jedoch auf unterschiedlichen Ebenen:

1.  **`is_divisible: bool`**: Dies ist eine **grundlegende, semantische Eigenschaft** des Gutscheinwerts. Sie beantwortet die Frage: "Kann der Wert, den dieser Gutschein repräsentiert, konzeptionell überhaupt geteilt werden?"
    * **Beispiel**: Ein Guthaben von 100€ ist teilbar (`is_divisible = true`). Ein Ticket für ein spezifisches Konzert ist es nicht (`is_divisible = false`).

2.  **`"split"` in `allowed_transaction_types`**: Dies ist eine **technische Berechtigung** für eine spezifische Operation in der Transaktionskette. Sie beantwortet die Frage: "Ist der *Mechanismus* 'split' für diesen Standard erlaubt?"

## Warum beide? Die vier Szenarien

Die Kombination beider Flags ermöglicht eine viel präzisere Steuerung und deckt wichtige Anwendungsfälle ab. Die folgende Tabelle zeigt die vier möglichen Kombinationen und ihre Bedeutung:

| `is_divisible` | `"split"` in `allowed_types`? | Bedeutung & Nutzen |
| :--- | :--- | :--- |
| **`true`** | **Ja** | ✅ **Normalfall für Währungen:** Der Wert ist teilbar und die Operation dafür ist erlaubt. (z.B. Minuto, Silber-Unzen) |
| **`false`** | **Nein** | ✅ **Normalfall für unteilbare Güter:** Der Wert ist nicht teilbar, die Operation ist konsequenterweise verboten. (z.B. ein Ticket) |
| `false` | Ja | ❌ **Logischer Widerspruch:** Ein Versuch, eine Split-Transaktion zu erstellen, schlägt fehl, da die Kernlogik zuerst die grundlegende `is_divisible`-Eigenschaft prüft. Die semantische Eigenschaft hat Vorrang und schützt das System. |
| **`true`** | **Nein** | 💡 **Wichtiger Sonderfall:** Beschreibt einen Wert, der *rechnerisch teilbar* ist (z.B. ein Guthaben), bei dem aber nur **vollständige Transfers des Restbetrags** erlaubt sind. Man kann den Gutschein nicht aufteilen, sondern nur "alles oder nichts" weitergeben. |

## Fazit

Die Beibehaltung beider Felder ist kein Versehen, sondern eine bewusste Entscheidung für ein **robusteres, sichereres und expressiveres** System.

* **Robustheit**: Logische Widersprüche im Standard führen nicht zu undefiniertem Verhalten.
* **Sicherheit**: Die grundlegende Eigenschaft (`is_divisible`) dient als übergeordneter Schutzschalter.
* **Expressivität**: Es ermöglicht Standard-Designern, komplexe und nützliche Verhaltensregeln zu definieren, wie im vierten Szenario gezeigt.