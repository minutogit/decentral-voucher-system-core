# Dokumentation: Transaktionsstruktur und Double-Spending-Erkennung

## 1\. Motivation und Designziele

Die Transaktionsstruktur in `voucher_core` wurde entwickelt, um zwei Hauptziele zu erreichen:

* **Interne Integrität:** Die Historie innerhalb einer einzelnen Gutschein-Datei muss fälschungssicher und kryptographisch nachvollziehbar sein.
* **Globale Validierung:** Es muss möglich sein, eine externe (Layer 2) Infrastruktur zur Erkennung von Double-Spending aufzubauen, ohne dabei die Anonymität der Nutzer oder die Details der Gutscheine preiszugeben.

Das Ergebnis ist eine mehrschichtige Sicherheitsarchitektur, die auf der expliziten kryptographischen Verkettung und einem spezifischen Signatur-Schema beruht.

## 2\. On-Voucher-Integrität: Die `prev_hash`-Kette

Jede Transaktion ist über das Feld `prev_hash` untrennbar mit ihrem Vorgänger verbunden.

* **Init-Transaktion:** Die allererste Transaktion (`t_type: "init"`) ist ein Sonderfall. Ihr `prev_hash` ist der Hash der finalen `voucher_id` des Gutscheins. Dies verankert die gesamte Transaktionskette fest mit der Identität des Gutscheins.
* **Folgetransaktionen:** Bei jeder weiteren Transaktion ist der `prev_hash` der SHA3-256-Hash des gesamten, kanonisch serialisierten Vorgänger-Transaktionsobjekts.

Diese Verkettung stellt sicher, dass die Reihenfolge der Transaktionen nicht unbemerkt verändert und keine Transaktion aus der Mitte entfernt werden kann, ohne die Kette zu brechen.

## 3\. Anatomie einer Transaktion

### Transaction ID (`t_id`)

Jede Transaktion besitzt eine eindeutige `t_id`. Diese wird berechnet, indem das Transaktionsobjekt selbst (mit temporär leeren `t_id`- und `sender_signature`-Feldern) kanonisch serialisiert und gehasht wird. Dies gibt jeder Transaktion eine von ihrem Inhalt abhängige, fälschungssichere Identität.

### Transaction Signature (`sender_signature`)

Dies ist der entscheidende Baustein für die externe Validierung. Die Signatur des Senders wird nicht über die gesamte Transaktion gebildet. Stattdessen wird ein spezifisches JSON-Objekt signiert, das nun auch den Zeitstempel der Transaktion (`t_time`) enthält:

```json
{
  "prev_hash": "...",
  "sender_id": "...",
  "t_id": "...",
  "t_time": "..."
}
```

Der Hash dieses Objekts wird mit dem privaten Schlüssel des Senders signiert. Diese bewusste Auswahl der signierten Daten ist der Schlüssel, der die folgende anonymisierte Double-Spending-Erkennung ermöglicht und eine zeitliche Einordnung des Betrugsversuchs erlaubt.

## 4\. Layer 2: Anonymisierte Double-Spending-Erkennung

Obwohl die `voucher_core`-Bibliothek selbst keine Serverlogik enthält, ist die Transaktionsstruktur so optimiert, dass eine übergeordnete Anwendung eine globale Datenbank (zentral oder dezentral) zur Betrugserkennung nutzen kann.

### Das Konzept des "Anonymen Fingerabdrucks"

Um einen Double-Spend global zu erkennen, muss ein Server wissen, ob ein Sender versucht, von demselben Zustand (`prev_hash`) zweimal auszugeben. Um dabei die Anonymität zu wahren, wird ein anonymer "Fingerabdruck" erzeugt.

* **Fingerabdruck:** `prvhash_senderid_hash` = `hash(prev_hash + sender_id)` (mittels einfacher Konkatenation).
* **Server-Upload:** Ein Client lädt nur die folgenden, anonymisierten Informationen an den Server hoch:
  * `prvhash_senderid_hash`
  * `t_id`
  * `sender_signature`
  * `t_time`

Der Server kennt weder den `prev_hash` noch die `sender_id` und kann diese auch nicht aus dem Hash zurückrechnen. Er kann also nicht sehen, wer handelt oder von welchem Gutschein die Transaktion stammt. Das Transaktionsdatum `t_time` wird für die zeitliche Einordnung mitgesendet und stellt für sich allein kein Datenschutzrisiko dar.

### Erkennung und Beweisführung

Ein Double-Spend hat stattgefunden, wenn der Server einen Eintrag für einen `prvhash_senderid_hash` erhält, für den bereits ein Eintrag mit einer anderen `t_id` existiert. Der mitgesendete Zeitstempel `t_time` dient dabei als wichtige Heuristik.

### Beispiel: Ein Double-Spending-Versuch

Alice besitzt einen Gutschein und möchte diesen sowohl an Bob als auch an Carol ausgeben.

**Ausgangslage:**

* Die letzte Transaktion auf Alices Gutschein hat den Hash `PREV_HASH_123`.
* Alices User-ID ist `ALICE_ID_456`.
* Der anonyme Fingerabdruck für diesen Zustand ist `prvhash_senderid_hash_XYZ` = `hash("PREV_HASH_123" + "ALICE_ID_456")`.

**Transaktion A (an Bob, legitim):**

* Alice erstellt eine Transaktion an Bob. Der Zeitstempel ist `T_TIME_A`.
* Diese Transaktion erhält die ID `TID_A_789`.
* Alice signiert die Daten (`prev_hash: PREV_HASH_123`, `sender_id: ALICE_ID_456`, `t_id: TID_A_789`, `t_time: T_TIME_A`) und erhält die Signatur `SIG_A`.
* Sie gibt den aktualisierten Gutschein an Bob. Bobs Client lädt die Daten an den Server: (`prvhash_senderid_hash_XYZ`, `TID_A_789`, `SIG_A`, `T_TIME_A`).

**Transaktion B (an Carol, betrügerisch):**

* Alice nimmt nun ihren alten Gutschein-Stand und erstellt eine zweite Transaktion an Carol. Um die erste Transaktion zu entwerten, könnte sie versuchen, einen früheren Zeitstempel `T_TIME_B` (wobei `T_TIME_B` \< `T_TIME_A`) zu verwenden.
* `prev_hash` und `sender_id` sind identisch.
* Diese neue Transaktion erhält eine neue ID, `TID_B_ABC`.
* Alice signiert die neuen Daten (`prev_hash: PREV_HASH_123`, `sender_id: ALICE_ID_456`, `t_id: TID_B_ABC`, `t_time: T_TIME_B`) und erhält die Signatur `SIG_B`.
* Sie gibt diesen Gutschein an Carol.

**Erkennung und Beweis:**

* Carols Client berechnet ebenfalls den Fingerabdruck `prvhash_senderid_hash_XYZ`.
* Beim Versuch, `(prvhash_senderid_hash_XYZ, TID_B_ABC, SIG_B, T_TIME_B)` hochzuladen, schlägt der Server Alarm. Er hat bereits einen Eintrag für diesen Fingerabdruck.
* Der Server sendet den Beweis an Carols Client: den bereits existierenden Eintrag (`TID_A_789`, `SIG_A`, `T_TIME_A`).
* Carols Client hat nun zwei gültige, von Alice signierte Transaktionen, die beide vom selben `prev_hash` ausgehen. Er kann beide Signaturen unabhängig voneinander verifizieren:
  * Prüfung 1: `verify(SIG_A, data("PREV_HASH_123", "ALICE_ID_456", "TID_A_789", "T_TIME_A"))` -\> Erfolgreich
  * Prüfung 2: `verify(SIG_B, data("PREV_HASH_123", "ALICE_ID_456", "TID_B_ABC", "T_TIME_B"))` -\> Erfolgreich

Der Beweis ist erbracht. Alice hat nachweislich einen Double-Spend versucht. Durch den Vergleich der Zeitstempel `T_TIME_A` und `T_TIME_B` kann Carols Client eine fundierte Annahme treffen, welche die erste gültige Transaktion war. Insbesondere wenn eine Transaktion mit einem stark vordatierten Zeitstempel ankommt, kann eine Warnung ausgegeben werden, da dies ein starkes Indiz für einen Betrugsversuch ist. Carol kann die Annahme des Gutscheins sicher ablehnen.