# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

## [2.3] - 2026-05-29

### Behoben
- **Dreistufige Erkennung** für Server 2016 und ältere Systeme, bei denen der Registry-Wert `UEFICA2023Status` nicht existiert, das Zertifikat aber trotzdem in der Secure Boot DB vorhanden ist
- **Direkte Prüfung via `Get-SecureBootUEFI db`** als Fallback-Mechanismus hinzugefügt
- **`WindowsUEFICA2023Capable`** als zweite Erkennungsstufe integriert
- **AvailableUpdates-Bitmask-Analyse** hinzugefügt für präzisere Statuserkennung

## [2.2] - 2026-03-27

### Behoben
- `UEFICA2023Status` verwendet nun den korrekten Registry-Pfad (`Servicing`)
- Korrekter Datentyp `REG_SZ` statt `REG_DWORD` für den Registry-Wert

## [2.1] - 2026-03-27

### Behoben
- `AllowEmptyString`-Attribut korrekt gesetzt
- `ADPropertyValueCollection`-Konvertierung repariert
- TLS 1.2 wird global erzwungen, da Microsoft-Server TLS 1.0/1.1 nicht mehr akzeptieren

## [2.0] - 2026-03-27

### Hinzugefügt
- Erstversion mit automatischer Voraussetzungsprüfung
- Prüfung von Secure Boot Status und UEFI CA 2023 Zertifikatsstatus
- CSV- und HTML-Report-Generierung
- Active Directory Integration zur Erfassung aller Computerobjekte
- BIOS/UEFI-, TPM- und Betriebssystem-Informationen
- Automatische RSAT-Installation und WinRM-Konfiguration
- Parallele Verarbeitung für schnelle Ausführung
- Detailliertes Logging
