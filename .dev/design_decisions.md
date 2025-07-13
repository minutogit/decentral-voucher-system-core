.dev/design_decisions.md

**Abbildung des Geschlechts im `Creator` Struct:**
    * **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `STRING` mit den erwarteten Werten "male", "female" und "unknown" definiert.
    * **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken, die vorwiegend in westlichen Ländern verbreitet sind. Sie bietet eine einfache und ausreichende Abbildung für die Zwecke der Core-Bibliothek (z.B. für Bürgen-Anforderungen des Minuto-Standards) und überlässt komplexere oder sensiblere Abbildungen den höheren Anwendungsschichten, die `voucher_core` nutzen.


