# 🛡️ Secure Boot Zertifikatsstatus Check

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202016%2B-lightgrey.svg)](https://www.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.3-brightgreen.svg)]()
[![Checks](https://img.shields.io/badge/Checks-SecureBoot%2C%20UEFI%2C%20TPM-orange.svg)]()

> Ein PowerShell-Skript zur automatisierten Überprüfung des Secure Boot Zertifikatsstatus (inkl. UEFI CA 2023/2026) aller Computer und Server in einer Active Directory Domäne. Mit CSV- und HTML-Report, umfassender Voraussetzungsprüfung und Logging.

## 📑 Inhaltsverzeichnis

- [Features](#-features)
- [Systemanforderungen](#-systemanforderungen)
- [Installation](#-installation)
- [Verwendung](#-verwendung)
- [Report-Ausgabe](#-report-ausgabe)
- [Änderungshistorie](#-änderungshistorie)
- [License](#-license)

---

## ✨ Features

- 🔒 **Secure Boot & UEFI CA 2023/2026 Statusprüfung** für alle AD-Computer
- ⚙️ **Automatische Voraussetzungsprüfung** (Adminrechte, PowerShell-Version, RSAT, WinRM, Firewall, Speicherplatz)
- 🏢 **Active Directory Integration**: Sammelt alle relevanten Computerobjekte
- 📝 **CSV- und HTML-Report** mit allen Ergebnissen
- 🖥️ **BIOS/UEFI-, TPM- und OS-Informationen** werden gesammelt
- 🚦 **Dreistufige Erkennung**: Registry, Capable-Flag, Secure Boot DB
- 📋 **Detailliertes Logging** im Log-Verzeichnis
- ⚡ **Parallele Verarbeitung** für schnelle Ausführung
- 🔧 **Parameter für OU-Filter und Parallelität**

## 💻 Systemanforderungen

- **Windows Server 2016**, Windows 11 oder neuer
- **PowerShell 5.1+**
- **RSAT / AD-Tools** installiert (ActiveDirectory-Modul)
- **Domain Admin**-Rechte empfohlen
- **WinRM** auf Zielsystemen aktiviert
- Ausführung auf einem Domänenmitglied mit AD-Connectivity

## 🚀 Installation

```powershell
# Repository klonen
# (Beispiel)
git clone https://github.com/<DEIN-USERNAME>/SecureBoot-Check.git
cd SecureBoot-Check
```

## ▶️ Verwendung

```powershell
# Standardausführung (empfohlen)
.\Check-SecureBootCertStatus.ps1

# Voraussetzungsprüfung überspringen (nur für bekannte Umgebungen)
.\Check-SecureBootCertStatus.ps1 -SkipVoraussetzungspruefung

# Nur bestimmte OU durchsuchen
.\Check-SecureBootCertStatus.ps1 -SearchBase "OU=Server,DC=domain,DC=local"

# Maximale parallele Verbindungen anpassen
.\Check-SecureBootCertStatus.ps1 -MaxParallel 16
```

## 📊 Report-Ausgabe

- **CSV-Report:** Übersicht aller geprüften Systeme und deren Secure Boot Status
- **HTML-Report:** Lesbarer Bericht für Management und IT
- **Log-Dateien:** Detaillierte Ablauf- und Fehlerprotokolle im Log-Verzeichnis (Standard: `C:\ExchangeMigrationLog`)

## 📝 Änderungshistorie

- **v2.0:** Erstversion mit automatischer Voraussetzungsprüfung
- **v2.1:** Bugfixes (AllowEmptyString, ADPropertyValueCollection, TLS 1.2)
- **v2.2:** Bugfixes Registry-Pfad und Datentyp
- **v2.3:** Dreistufige Erkennung, Fallback-Prüfung, Bitmask-Analyse

## � Contributors

- [@RoccoAmmon](https://github.com/RoccoAmmon)
- [Claude](https://claude.ai) (AI Assistant by Anthropic)

## �📄 License

MIT

---
Dieses Skript ist für IT-Administratoren konzipiert, die den Secure Boot Zertifikatsstatus in Windows-Umgebungen zentral prüfen und dokumentieren möchten.
