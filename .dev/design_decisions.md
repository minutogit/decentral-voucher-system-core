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

### Warum ist die Berechnung scheinbar komplex?
Die Berechnung ist nicht willkürlich komplex, sondern präzise darauf ausgelegt, einen kritischen Anwendungsfall robust zu handhaben: die **lokale Double-Spending-Erkennung**.
Die Komplexität entsteht, weil die Logik zwischen zwei Zuständen eines Gutscheins im Profil des Nutzers unterscheiden muss:
1.  **Aktiver (spendabler) Gutschein:** Der Nutzer besitzt ein Guthaben `> 0`. Die ID muss diesen aktuellsten, besessenen Zustand widerspiegeln.
2.  **Archivierter (ausgegebener) Gutschein:** Der Nutzer hat das gesamte Guthaben ausgegeben (Guthaben `= 0`). Der Gutschein wird aber als "leere Hülle" für die Transaktionshistorie aufbewahrt. Seine ID muss auf dem **letzten Zustand eingefroren werden, in dem er aktiv war**.
Um dies zu erreichen, kann die Berechnung nicht einfach die letzte Transaktion des Gutscheins nehmen. Stattdessen muss sie die Transaktionshistorie **rückwärts durchsuchen**, um den letzten Zeitpunkt zu finden, an dem der Profilinhaber tatsächlich ein Guthaben besaß. Dieser gezielte Suchvorgang macht die Berechnung scheinbar komplex, ist aber die Grundlage für eine konsistente und sichere Zustandsverwaltung.
