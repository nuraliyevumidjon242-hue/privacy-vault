# Verzeichnis von Verarbeitungstätigkeiten (Muster nach Art. 30 DSGVO)

> **Muster, keine Rechtsberatung.** Verantwortliche müssen alle Beispielangaben, insbesondere Rechtsgrundlage, Fristen, Empfänger und tatsächliche TOMs, mit dem realen Betrieb abgleichen.

## 1. Verantwortlicher

| Feld | Beispiel / auszufüllen |
|---|---|
| Verantwortlicher | Betreiber von PrivacyVault (Name und Anschrift vor Produktivbetrieb eintragen) |
| Vertretung in der EU | Nur falls erforderlich; eintragen |
| Datenschutzbeauftragte/r | Kontakt eintragen, falls benannt |

## 2. Verarbeitung

| Feld | Eintrag |
|---|---|
| Bezeichnung | Benutzerkonto, Authentifizierung und Verwaltung von Datenschutzrechten |
| Zwecke | Konto bereitstellen; Anfragen authentifizieren; gespeicherte Profildaten berichtigen, ausgeben oder löschen; Einwilligungen verwalten; Sicherheitsereignisse nachvollziehbar machen |
| Betroffene Personen | Registrierte Nutzerinnen und Nutzer |
| Datenkategorien | E-Mail-Adresse; optional Vor- und Nachname, Telefonnummer, Anschrift und Geburtsdatum; Passwort-Hash; Sitzungs-/Refresh-Token-Hash; Einwilligungsereignisse; pseudonyme Audit- und Löschungsnachweise |
| Besondere Kategorien nach Art. 9 | Im Muster nicht vorgesehen; keine solchen Felder hinzufügen, ohne Rechtsgrundlage, Schutzbedarf und DPIA zu prüfen |
| Datenquellen | Direkt von der betroffenen Person über die API |
| Empfänger / Kategorien | Autorisierte Betriebsadministration (Audit-Metadaten, keine entschlüsselten Nutzerdaten); Hosting-/Datenbank-/KMS-Anbieter entsprechend gewähltem Deployment und Auftragsverarbeitungsvertrag |
| Drittlandübermittlung | Im Muster nicht festgelegt; Region und Anbieter vor Betrieb eintragen und Übermittlungsgrundlage prüfen |
| Löschfristen | Kontodaten bis Löschung oder dokumentierte gesetzliche Aufbewahrung; standardmäßig 14 Tage Widerrufs-/Grace-Zeitraum für geplante Löschung; Audit-Logs standardmäßig 365 Tage; pseudonyme Löschungsnachweise standardmäßig 365 Tage; Einwilligungsereignisse standardmäßig 1095 Tage; inaktive Konten nach 730 Tagen auf `INACTIVE` gesetzt, nicht automatisch gelöscht; Fristen pro Zweck rechtlich festlegen |
| Technische Beschreibung | Spring Boot REST API, PostgreSQL 16, Flyway, stateless JWT, AES-256-GCM mit DEK, optional AWS KMS für DEK-Wrapping |

## 3. Technische und organisatorische Maßnahmen

- Verschlüsselung persönlicher Felder mit AES-GCM, zufälligem IV und AAD; separate HMAC-Schlüssel für Suchindex und pseudonyme Referenzen.
- Passwort-Hashing mit Argon2id; Refresh-Tokens nur als SHA-256-Hash gespeichert; kurzlebige Access-Tokens und Rotation.
- Rollen-/Statusprüfung, restriktive CORS-Konfiguration, Security-Header, Validierung und generische Authentifizierungsfehler.
- Append-orientierte Einwilligungshistorie; Audit-Ereignisse enthalten keine Klartext-Profildaten oder Authentifizierungsgeheimnisse.
- Löschung und Zugriff werden durch Hintergrundjobs, Container-Healthchecks und CI-Tests unterstützt.
- Betrieb benötigt zusätzlich: TLS, minimale IAM-/DB-Rechte, Geheimnisverwaltung, Backup- und Restore-Verfahren, Protokollüberwachung, Notfallkontakte und regelmäßige Berechtigungsreviews.

## 4. Prüfung und Pflege

| Feld | Eintrag |
|---|---|
| Verantwortliche Fachstelle | Vor Produktivbetrieb benennen |
| Überprüfung | Mindestens jährlich und bei Zweck-, Anbieter-, Daten- oder Architekturänderung |
| DPIA-Prüfung | Vor Einsatz beurteilen; bei voraussichtlich hohem Risiko eine Datenschutz-Folgenabschätzung prüfen |
| Letzte Aktualisierung | Bei Übernahme in ein reales System ausfüllen |
