#requires -RunAsAdministrator

<#
.SYNOPSIS
    Prueft alle Computer und Server im Unternehmen auf den Secure Boot Zertifikatsstatus (2023/2026 Update).
    Alle Voraussetzungen werden automatisch geprueft und bei Bedarf nachinstalliert.

.DESCRIPTION
    Dieses Skript:
    PHASE 1 - Voraussetzungspruefung:
    - Prueft ob das Skript als Administrator ausgefuehrt wird
    - Prueft die PowerShell-Version (Minimum 5.1)
    - Prueft und installiert das Active Directory PowerShell-Modul (RSAT-Tools)
    - Prueft und aktiviert WinRM (Windows Remote Management) lokal
    - Prueft die Domaenenmitgliedschaft des ausfuehrenden Computers
    - Prueft und konfiguriert die Firewall fuer WinRM
    - Erstellt das Log-Verzeichnis
    - Prueft verfuegbaren Speicherplatz

    PHASE 2 - Secure Boot Pruefung:
    - Verbindet sich mit allen Computern aus dem Active Directory
    - Prueft Secure Boot Status, UEFI CA 2023 Zertifikatsstatus
    - Dreistufige Erkennung: Registry-Status, Capable-Flag, direkte DB-Pruefung
    - Sammelt BIOS/UEFI, TPM und Betriebssystem-Informationen
    - Erstellt CSV-, HTML-Report und Log-Datei

.NOTES
    Autor:          Rocco Ammon
    Datum:          27.03.2026
    Version:        2.3
    Voraussetzung:  - Administratorrechte (wird automatisch geprueft)
                    - Domaenenmitgliedschaft
                    - Internetverbindung oder WSUS fuer Feature-Installation

    Aenderungshistorie:
    v2.0 - Erstversion mit automatischer Voraussetzungspruefung
    v2.1 - Bugfix: AllowEmptyString, ADPropertyValueCollection, TLS 1.2
    v2.2 - Bugfix: UEFICA2023Status korrekter Registry-Pfad (Servicing)
                    und korrekter Datentyp (REG_SZ statt REG_DWORD)
    v2.3 - Bugfix: Dreistufige Erkennung fuer Server 2016 und aeltere Systeme
                    bei denen UEFICA2023Status nicht existiert aber das
                    Zertifikat trotzdem in der Secure Boot DB vorhanden ist.
                    Direkte Pruefung via Get-SecureBootUEFI db als Fallback.
                    WindowsUEFICA2023Capable als zweite Erkennungsstufe.
                    AvailableUpdates-Bitmask-Analyse hinzugefuegt.

.EXAMPLE
    .\Check-SecureBootCertStatus.ps1
    Fuehrt die vollstaendige Pruefung inkl. aller Voraussetzungen durch.

.EXAMPLE
    .\Check-SecureBootCertStatus.ps1 -SkipVoraussetzungspruefung
    Ueberspringt die Voraussetzungspruefung (nur verwenden wenn Umgebung bekannt ist).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Ueberspringt die automatische Voraussetzungspruefung")]
    [switch]$SkipVoraussetzungspruefung,

    [Parameter(Mandatory = $false, HelpMessage = "Bestimmte OU im AD durchsuchen")]
    [string]$SearchBase = "",

    [Parameter(Mandatory = $false, HelpMessage = "Maximale parallele Verbindungen")]
    [int]$MaxParallel = 32
)

# ============================================================================
# region VARIABLEN-DEFINITION
# ============================================================================

# --- TLS 1.2 global erzwingen (erforderlich fuer Downloads von Microsoft) ---
# =========================================================================
# BUGFIX v2.1: PowerShell 5.1 verwendet standardmaessig TLS 1.0/1.1,
# aber Microsoft-Download-Server akzeptieren nur noch TLS 1.2+.
# =========================================================================
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Pfad- und Datei-Variablen ---
[string]$LogVerzeichnis               = "C:\ScriptLog"
[string]$Zeitstempel                   = Get-Date -Format "yyyyMMdd_HHmmss"
[string]$LogDateiPfad                  = Join-Path -Path $LogVerzeichnis -ChildPath "SecureBoot_Zertifikatspruefung_$Zeitstempel.log"
[string]$CsvExportPfad                 = Join-Path -Path $LogVerzeichnis -ChildPath "SecureBoot_Zertifikatsstatus_$Zeitstempel.csv"
[string]$HtmlExportPfad                = Join-Path -Path $LogVerzeichnis -ChildPath "SecureBoot_Zertifikatsstatus_$Zeitstempel.html"
[string]$VoraussetzungenLogPfad        = Join-Path -Path $LogVerzeichnis -ChildPath "SecureBoot_Voraussetzungspruefung_$Zeitstempel.log"

# --- Mindestanforderungen ---
[version]$MinPowerShellVersion         = "5.1"
[int]$MinSpeicherplatzMB               = 100
[string]$MinBetriebssystem             = "Windows Server 2016"

# --- Active Directory Variablen ---
[string]$ADSearchBase                  = $SearchBase
[string[]]$BetriebssystemFilter        = @("*Windows*")
[bool]$NurAktiveComputer               = $true

# --- Verbindungs-Variablen ---
[int]$ThrottleLimit                    = $MaxParallel
[int]$PingTimeoutMs                    = 1000
[int]$WinRMTimeoutSek                  = 30

# --- Registry-Pfade fuer Secure Boot Pruefung ---
[string]$RegPfadSecureBoot             = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
[string]$RegWertSecureBoot             = "UEFISecureBootEnabled"
[string]$RegPfadUEFICA2023             = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
[string]$RegWertUEFICA2023             = "UEFICA2023Status"

# --- Zusaetzliche Registry-Pfade fuer erweiterte Pruefung ---
[string]$RegPfadAvailableUpdates       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
[string]$RegWertAvailableUpdates       = "AvailableUpdates"
[string]$RegWertUEFICA2023Error        = "UEFICA2023Error"
[string]$RegWertWindowsUEFICA2023Cap   = "WindowsUEFICA2023Capable"

# --- Suchstring fuer direkte Zertifikatspruefung in der Secure Boot DB ---
[string]$ZertifikatSuchstring          = "Windows UEFI CA 2023"

# --- AvailableUpdates Bitmask-Bedeutungen (laut Microsoft KB5068202) ---
[hashtable]$AvailableUpdatesBits       = @{
    0x0004 = "DB-Update (2023 CA Zertifikat)"
    0x0040 = "Neuer Boot-Manager"
    0x0100 = "DBX-Update (Sperrliste)"
    0x0800 = "KEK-Update"
    0x1000 = "2023 Boot-Manager-Update"
    0x4000 = "2023 Boot-Manager Final"
}

# --- Zertifikats-Schwellenwerte ---
[int]$BiosMindestJahr                  = 2023

# --- Zaehler-Variablen ---
[int]$GesamtComputer                   = 0
[int]$ErreichbareComputer              = 0
[int]$NichtErreichbareComputer         = 0
[int]$SecureBootAktiv                  = 0
[int]$SecureBootInaktiv                = 0
[int]$ZertifikatAktualisiert           = 0
[int]$ZertifikatNichtAktualisiert      = 0
[int]$FehlerAnzahl                     = 0

# --- Voraussetzungs-Status ---
[hashtable]$VoraussetzungsStatus       = @{
    Administrator          = $false
    PowerShellVersion      = $false
    ADModul                = $false
    WinRM                  = $false
    Domaenenmitglied       = $false
    LogVerzeichnis         = $false
    Speicherplatz          = $false
    Firewall               = $false
    NuGetProvider          = $false
    Netzwerkverbindung     = $false
}

# --- Ergebnis-Array ---
[System.Collections.ArrayList]$ErgebnisListe = [System.Collections.ArrayList]::new()

# endregion VARIABLEN-DEFINITION
# ============================================================================

# ============================================================================
# region LOGGING-FUNKTION (wird zuerst definiert, da ueberall benoetigt)
# ============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Schreibt eine Nachricht in die Log-Datei und optional in die Konsole.
    .PARAMETER Nachricht
        Die zu protokollierende Nachricht. Leere Zeichenfolgen sind erlaubt.
    .PARAMETER Level
        Der Log-Level: INFO, WARNUNG, FEHLER, ERFOLG, PHASE.
    .PARAMETER InKonsole
        Gibt die Nachricht auch in der Konsole aus (Standard: $true).
    .EXAMPLE
        Write-Log -Nachricht "Vorgang gestartet" -Level "INFO"
    #>
    [CmdletBinding()]
    param(
        # BUGFIX v2.1: [AllowEmptyString()] fuer leere Trennzeilen
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Nachricht,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNUNG", "FEHLER", "ERFOLG", "PHASE")]
        [string]$Level = "INFO",

        [Parameter(Mandatory = $false)]
        [bool]$InKonsole = $true
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Nachricht)) {
            if ($InKonsole) { Write-Host "" }
            return
        }

        [string]$LogZeitstempel = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        [string]$LogEintrag = "[$LogZeitstempel] [$Level] $Nachricht"

        if (Test-Path -Path (Split-Path $LogDateiPfad -Parent)) {
            Add-Content -Path $LogDateiPfad -Value $LogEintrag -Encoding UTF8 -ErrorAction SilentlyContinue
        }

        if ($InKonsole) {
            switch ($Level) {
                "INFO"     { Write-Host $LogEintrag -ForegroundColor Cyan }
                "WARNUNG"  { Write-Host $LogEintrag -ForegroundColor Yellow }
                "FEHLER"   { Write-Host $LogEintrag -ForegroundColor Red }
                "ERFOLG"   { Write-Host $LogEintrag -ForegroundColor Green }
                "PHASE"    { Write-Host "" ; Write-Host $LogEintrag -ForegroundColor Magenta -BackgroundColor Black }
            }
        }
    }
    catch {
        Write-Warning "Log-Schreiben fehlgeschlagen: $($_.Exception.Message)"
    }
}

# endregion LOGGING-FUNKTION
# ============================================================================

# ============================================================================
# region PHASE 1: VORAUSSETZUNGSPRUEFUNG UND AUTO-INSTALLATION
# ============================================================================

function Test-AlleVoraussetzungen {
    <#
    .SYNOPSIS
        Prueft alle Voraussetzungen fuer die Skriptausfuehrung und installiert
        fehlende Komponenten automatisch nach.
    .DESCRIPTION
        Prueft und korrigiert:
        1.  Administratorrechte
        2.  PowerShell-Version
        3.  Log-Verzeichnis
        4.  Speicherplatz
        5.  NuGet Package Provider (inkl. TLS 1.2 Erzwingung)
        6.  Active Directory PowerShell-Modul (RSAT)
        7.  Domaenenmitgliedschaft
        8.  WinRM-Dienst
        9.  Firewall-Regeln fuer WinRM
        10. Netzwerkkonnektivitaet zum Domaenencontroller
    .EXAMPLE
        Test-AlleVoraussetzungen
    #>

    Write-Log -Nachricht "============================================================" -Level "PHASE"
    Write-Log -Nachricht "  PHASE 1: AUTOMATISCHE VORAUSSETZUNGSPRUEFUNG              " -Level "PHASE"
    Write-Log -Nachricht "============================================================" -Level "PHASE"

    [int]$PruefungNummer             = 0
    [int]$PruefungenGesamt           = 10
    [int]$ErfolgreichePruefungen     = 0
    [int]$FehlgeschlagenePruefungen  = 0
    [bool]$KritischerFehler          = $false

    # -----------------------------------------------------------------------
    # PRUEFUNG 1: Administratorrechte
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe Administratorrechte..." -Level "INFO"

    try {
        $AktuellerBenutzer = [Security.Principal.WindowsIdentity]::GetCurrent()
        $AdminPrincipal    = New-Object Security.Principal.WindowsPrincipal($AktuellerBenutzer)
        $IstAdmin          = $AdminPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($IstAdmin) {
            $VoraussetzungsStatus.Administrator = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] Skript wird als Administrator ausgefuehrt (Benutzer: $($AktuellerBenutzer.Name))" -Level "ERFOLG"
        }
        else {
            $VoraussetzungsStatus.Administrator = $false
            $FehlgeschlagenePruefungen++
            $KritischerFehler = $true
            Write-Log -Nachricht "  [FEHLER] Skript wird NICHT als Administrator ausgefuehrt!" -Level "FEHLER"
            Write-Log -Nachricht "  -> Bitte starten Sie PowerShell als Administrator und fuehren Sie das Skript erneut aus." -Level "FEHLER"
        }
    }
    catch {
        Write-Log -Nachricht "  [FEHLER] Administratorrechte konnten nicht geprueft werden: $($_.Exception.Message)" -Level "FEHLER"
        $KritischerFehler = $true
        $FehlgeschlagenePruefungen++
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 2: PowerShell-Version
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe PowerShell-Version (Minimum: $MinPowerShellVersion)..." -Level "INFO"

    try {
        [version]$AktuellePSVersion = $PSVersionTable.PSVersion

        if ($AktuellePSVersion -ge $MinPowerShellVersion) {
            $VoraussetzungsStatus.PowerShellVersion = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] PowerShell-Version: $AktuellePSVersion (Edition: $($PSVersionTable.PSEdition))" -Level "ERFOLG"

            if ($AktuellePSVersion.Major -ge 7) {
                Write-Log -Nachricht "  [INFO] PowerShell 7+ erkannt - Parallelisierung mit ForEach-Object -Parallel verfuegbar" -Level "INFO"
            }
        }
        else {
            $VoraussetzungsStatus.PowerShellVersion = $false
            $FehlgeschlagenePruefungen++
            $KritischerFehler = $true
            Write-Log -Nachricht "  [FEHLER] PowerShell-Version $AktuellePSVersion ist zu alt! Minimum: $MinPowerShellVersion" -Level "FEHLER"

            try {
                $OSVersion = [System.Environment]::OSVersion.Version
                if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -ge 1) {
                    Write-Log -Nachricht "  -> Windows Management Framework 5.1 muss manuell installiert werden." -Level "WARNUNG"
                    Write-Log -Nachricht "  -> Download: https://www.microsoft.com/en-us/download/details.aspx?id=54616" -Level "INFO"
                }
                else {
                    Write-Log -Nachricht "  -> Bitte fuehren Sie Windows Update aus und starten Sie das Skript erneut." -Level "INFO"
                }
            }
            catch {
                Write-Log -Nachricht "  -> Automatisches Update nicht moeglich: $($_.Exception.Message)" -Level "FEHLER"
            }
        }
    }
    catch {
        Write-Log -Nachricht "  [FEHLER] PowerShell-Version konnte nicht ermittelt werden: $($_.Exception.Message)" -Level "FEHLER"
        $FehlgeschlagenePruefungen++
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 3: Log-Verzeichnis erstellen
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe und erstelle Log-Verzeichnis: $LogVerzeichnis" -Level "INFO"

    try {
        if (Test-Path -Path $LogVerzeichnis) {
            $VoraussetzungsStatus.LogVerzeichnis = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] Log-Verzeichnis existiert bereits." -Level "ERFOLG"
        }
        else {
            Write-Log -Nachricht "  -> Log-Verzeichnis wird erstellt..." -Level "INFO"
            New-Item -Path $LogVerzeichnis -ItemType Directory -Force -ErrorAction Stop | Out-Null

            $ACL = Get-Acl -Path $LogVerzeichnis
            $AdminRegel = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $ACL.SetAccessRule($AdminRegel)
            Set-Acl -Path $LogVerzeichnis -AclObject $ACL -ErrorAction SilentlyContinue

            $VoraussetzungsStatus.LogVerzeichnis = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] Log-Verzeichnis erfolgreich erstellt: $LogVerzeichnis" -Level "ERFOLG"
        }
    }
    catch {
        $VoraussetzungsStatus.LogVerzeichnis = $false
        $FehlgeschlagenePruefungen++
        $KritischerFehler = $true
        Write-Log -Nachricht "  [FEHLER] Log-Verzeichnis konnte nicht erstellt werden: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 4: Speicherplatz
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe verfuegbaren Speicherplatz auf $(Split-Path $LogVerzeichnis -Qualifier)..." -Level "INFO"

    try {
        $Laufwerk       = Split-Path $LogVerzeichnis -Qualifier
        $LaufwerkInfo   = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Laufwerk'" -ErrorAction Stop
        $FreierPlatzMB  = [math]::Round($LaufwerkInfo.FreeSpace / 1MB, 2)
        $FreierPlatzGB  = [math]::Round($LaufwerkInfo.FreeSpace / 1GB, 2)

        if ($FreierPlatzMB -ge $MinSpeicherplatzMB) {
            $VoraussetzungsStatus.Speicherplatz = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] Freier Speicherplatz auf ${Laufwerk}: $FreierPlatzGB GB ($FreierPlatzMB MB)" -Level "ERFOLG"
        }
        else {
            $VoraussetzungsStatus.Speicherplatz = $false
            $FehlgeschlagenePruefungen++
            Write-Log -Nachricht "  [WARNUNG] Nur $FreierPlatzMB MB frei auf ${Laufwerk}. Mindestens $MinSpeicherplatzMB MB empfohlen." -Level "WARNUNG"

            try {
                Write-Log -Nachricht "  -> Versuche alte Log-Dateien zu bereinigen (aelter als 90 Tage)..." -Level "INFO"
                $AlteDateien = Get-ChildItem -Path $LogVerzeichnis -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) }

                if ($AlteDateien.Count -gt 0) {
                    $AlteDateien | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log -Nachricht "  -> $($AlteDateien.Count) alte Dateien bereinigt." -Level "ERFOLG"
                }
                else {
                    Write-Log -Nachricht "  -> Keine alten Dateien zum Bereinigen gefunden." -Level "INFO"
                }
            }
            catch {
                Write-Log -Nachricht "  -> Automatische Bereinigung fehlgeschlagen: $($_.Exception.Message)" -Level "WARNUNG"
            }
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        Write-Log -Nachricht "  [FEHLER] Speicherplatzpruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 5: NuGet Package Provider (mit TLS 1.2 Erzwingung)
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe NuGet Package Provider..." -Level "INFO"

    try {
        # BUGFIX v2.1: TLS 1.2 erzwingen vor NuGet-Download
        [string]$AktuellesTLS = [Net.ServicePointManager]::SecurityProtocol
        Write-Log -Nachricht "  -> Aktuelles TLS-Protokoll: $AktuellesTLS" -Level "INFO"

        if ($AktuellesTLS -notmatch "Tls12") {
            Write-Log -Nachricht "  -> TLS 1.2 ist NICHT aktiv. Erzwinge TLS 1.2..." -Level "WARNUNG"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Write-Log -Nachricht "  -> TLS-Protokoll jetzt: $([Net.ServicePointManager]::SecurityProtocol)" -Level "INFO"
        }
        else {
            Write-Log -Nachricht "  -> TLS 1.2 ist bereits aktiv." -Level "INFO"
        }

        # TLS 1.2 permanent in Registry setzen
        try {
            $RegPfad64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
            if (Test-Path -Path $RegPfad64) {
                $AktuellerWert64 = Get-ItemProperty -Path $RegPfad64 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
                if ($null -eq $AktuellerWert64 -or $AktuellerWert64.SchUseStrongCrypto -ne 1) {
                    Set-ItemProperty -Path $RegPfad64 -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction Stop
                    Write-Log -Nachricht "  -> Registry: TLS 1.2 fuer 64-Bit .NET permanent aktiviert." -Level "INFO"
                }
            }

            $RegPfad32 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
            if (Test-Path -Path $RegPfad32) {
                $AktuellerWert32 = Get-ItemProperty -Path $RegPfad32 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
                if ($null -eq $AktuellerWert32 -or $AktuellerWert32.SchUseStrongCrypto -ne 1) {
                    Set-ItemProperty -Path $RegPfad32 -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction Stop
                    Write-Log -Nachricht "  -> Registry: TLS 1.2 fuer 32-Bit .NET permanent aktiviert." -Level "INFO"
                }
            }
            Write-Log -Nachricht "  -> TLS 1.2 permanent konfiguriert." -Level "ERFOLG"
        }
        catch {
            Write-Log -Nachricht "  -> Registry-Aenderung fuer TLS 1.2 fehlgeschlagen: $($_.Exception.Message)" -Level "WARNUNG"
        }

        # NuGet pruefen und installieren
        $NuGetInstalliert = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue

        if ($null -ne $NuGetInstalliert) {
            $VoraussetzungsStatus.NuGetProvider = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] NuGet Provider ist installiert (Version: $($NuGetInstalliert.Version))" -Level "ERFOLG"
        }
        else {
            Write-Log -Nachricht "  -> NuGet Provider wird installiert (mit TLS 1.2)..." -Level "INFO"

            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
                $VoraussetzungsStatus.NuGetProvider = $true
                $ErfolgreichePruefungen++
                Write-Log -Nachricht "  [OK] NuGet Provider erfolgreich installiert." -Level "ERFOLG"
            }
            catch {
                Write-Log -Nachricht "  [WARNUNG] Online-Installation fehlgeschlagen: $($_.Exception.Message)" -Level "WARNUNG"

                try {
                    $NuGetDllPfade = @(
                        "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget",
                        "$env:LOCALAPPDATA\PackageManagement\ProviderAssemblies\nuget",
                        "$env:ProgramFiles\PackageManagement\ProviderAssemblies"
                    )

                    [bool]$NuGetOfflineGefunden = $false
                    foreach ($Pfad in $NuGetDllPfade) {
                        if (Test-Path -Path "$Pfad\*nuget*" -ErrorAction SilentlyContinue) {
                            Write-Log -Nachricht "  -> NuGet-Dateien gefunden in: $Pfad" -Level "INFO"
                            $NuGetOfflineGefunden = $true
                            break
                        }
                    }

                    if (-not $NuGetOfflineGefunden) {
                        Write-Log -Nachricht "  -> MANUELLE INSTALLATION ERFORDERLICH:" -Level "WARNUNG"
                        Write-Log -Nachricht "  -> 1. Laden Sie NuGet herunter: Invoke-WebRequest -Uri 'https://onegetcdn.azureedge.net/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll' -OutFile 'NuGet.dll'" -Level "INFO"
                        Write-Log -Nachricht "  -> 2. Kopieren nach: $env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\" -Level "INFO"
                    }

                    $FehlgeschlagenePruefungen++
                    Write-Log -Nachricht "  [WARNUNG] NuGet nicht verfuegbar - beeintraechtigt NICHT die Secure Boot Pruefung." -Level "WARNUNG"
                }
                catch {
                    $FehlgeschlagenePruefungen++
                    Write-Log -Nachricht "  [WARNUNG] NuGet Offline-Fallback fehlgeschlagen: $($_.Exception.Message)" -Level "WARNUNG"
                }
            }
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        Write-Log -Nachricht "  [WARNUNG] NuGet-Pruefung fehlgeschlagen: $($_.Exception.Message)" -Level "WARNUNG"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 6: Active Directory PowerShell-Modul (RSAT)
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe Active Directory PowerShell-Modul..." -Level "INFO"

    try {
        $ADModulVerfuegbar = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue

        if ($null -ne $ADModulVerfuegbar) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $VoraussetzungsStatus.ADModul = $true
                $ErfolgreichePruefungen++
                Write-Log -Nachricht "  [OK] Active Directory Modul geladen (Version: $($ADModulVerfuegbar.Version))" -Level "ERFOLG"
            }
            catch {
                Write-Log -Nachricht "  [WARNUNG] AD-Modul installiert, Laden fehlgeschlagen. Versuche Reparatur..." -Level "WARNUNG"
                try {
                    Import-Module ActiveDirectory -Force -ErrorAction Stop
                    $VoraussetzungsStatus.ADModul = $true
                    $ErfolgreichePruefungen++
                    Write-Log -Nachricht "  [OK] Active Directory Modul nach Reparatur geladen." -Level "ERFOLG"
                }
                catch {
                    $FehlgeschlagenePruefungen++
                    $KritischerFehler = $true
                    Write-Log -Nachricht "  [FEHLER] AD-Modul konnte nicht geladen werden." -Level "FEHLER"
                }
            }
        }
        else {
            Write-Log -Nachricht "  -> AD Modul NICHT installiert. Starte Installation..." -Level "WARNUNG"

            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $IstServer = $OSInfo.ProductType -ne 1

            if ($IstServer) {
                try {
                    Import-Module ServerManager -ErrorAction Stop
                    $RSATFeature = Get-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction Stop

                    if ($RSATFeature.InstallState -eq "Available") {
                        Write-Log -Nachricht "  -> Installiere RSAT-AD-PowerShell Feature..." -Level "INFO"
                        $InstallResult = Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature -ErrorAction Stop
                        if ($InstallResult.Success) {
                            Write-Log -Nachricht "  [OK] RSAT-AD-PowerShell installiert." -Level "ERFOLG"
                            if ($InstallResult.RestartNeeded -eq "Yes") {
                                Write-Log -Nachricht "  [WARNUNG] Neustart erforderlich!" -Level "WARNUNG"
                            }
                        }
                    }
                    elseif ($RSATFeature.InstallState -eq "Installed") {
                        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature -ErrorAction Stop | Out-Null
                    }

                    @("RSAT-AD-Tools", "RSAT-ADDS-Tools") | ForEach-Object {
                        try {
                            $F = Get-WindowsFeature -Name $_ -ErrorAction SilentlyContinue
                            if ($null -ne $F -and $F.InstallState -eq "Available") {
                                Install-WindowsFeature -Name $_ -ErrorAction SilentlyContinue | Out-Null
                            }
                        } catch { }
                    }
                }
                catch {
                    Write-Log -Nachricht "  [FEHLER] ServerManager fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
                    try {
                        $DISMResult = & dism.exe /Online /Add-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /NoRestart 2>&1
                        if ($LASTEXITCODE -eq 0) { Write-Log -Nachricht "  [OK] RSAT via DISM installiert." -Level "ERFOLG" }
                    }
                    catch { Write-Log -Nachricht "  [FEHLER] DISM-Fallback fehlgeschlagen." -Level "FEHLER" }
                }
            }
            else {
                try {
                    $RSATCap = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*" -ErrorAction Stop
                    if ($RSATCap.State -eq "NotPresent") {
                        Write-Log -Nachricht "  -> Installiere RSAT via Windows Capability..." -Level "INFO"
                        Add-WindowsCapability -Online -Name $RSATCap.Name -ErrorAction Stop | Out-Null
                        Write-Log -Nachricht "  [OK] RSAT installiert." -Level "ERFOLG"
                    }
                }
                catch {
                    try {
                        & dism.exe /Online /Add-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /NoRestart 2>&1 | Out-Null
                    }
                    catch { Write-Log -Nachricht "  [FEHLER] Alle Installationsmethoden erschoepft." -Level "FEHLER" }
                }
            }

            try {
                Start-Sleep -Seconds 3
                Import-Module ActiveDirectory -Force -ErrorAction Stop
                $VoraussetzungsStatus.ADModul = $true
                $ErfolgreichePruefungen++
                Write-Log -Nachricht "  [OK] AD Modul nach Installation geladen." -Level "ERFOLG"
            }
            catch {
                $VoraussetzungsStatus.ADModul = $false
                $FehlgeschlagenePruefungen++
                $KritischerFehler = $true
                Write-Log -Nachricht "  [FEHLER] AD-Modul konnte nicht geladen werden. Neustart erforderlich?" -Level "FEHLER"
            }
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        $KritischerFehler = $true
        Write-Log -Nachricht "  [FEHLER] AD-Modul-Pruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 7: Domaenenmitgliedschaft
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe Domaenenmitgliedschaft..." -Level "INFO"

    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        if ($ComputerSystem.PartOfDomain) {
            $VoraussetzungsStatus.Domaenenmitglied = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] Domaenenmitglied: $($ComputerSystem.Domain) ($($ComputerSystem.Name))" -Level "ERFOLG"
        }
        else {
            $VoraussetzungsStatus.Domaenenmitglied = $false
            $FehlgeschlagenePruefungen++
            $KritischerFehler = $true
            Write-Log -Nachricht "  [FEHLER] Computer ist KEIN Domaenenmitglied!" -Level "FEHLER"
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        Write-Log -Nachricht "  [FEHLER] Domaenenpruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 8: WinRM-Dienst
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe WinRM-Dienst..." -Level "INFO"

    try {
        $WinRMDienst = Get-Service -Name "WinRM" -ErrorAction Stop

        if ($WinRMDienst.Status -eq "Running") {
            $VoraussetzungsStatus.WinRM = $true
            $ErfolgreichePruefungen++
            Write-Log -Nachricht "  [OK] WinRM laeuft (Starttyp: $($WinRMDienst.StartType))" -Level "ERFOLG"
        }
        else {
            Write-Log -Nachricht "  -> WinRM nicht gestartet. Konfiguriere..." -Level "WARNUNG"
            try {
                Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
                Set-Service -Name "WinRM" -StartupType Automatic -ErrorAction Stop
                Start-Service -Name "WinRM" -ErrorAction Stop
                Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force -ErrorAction SilentlyContinue
                Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024 -Force -ErrorAction SilentlyContinue
                Set-Item -Path WSMan:\localhost\Shell\MaxConcurrentUsers -Value 25 -Force -ErrorAction SilentlyContinue

                $WinRMNeu = Get-Service -Name "WinRM" -ErrorAction Stop
                if ($WinRMNeu.Status -eq "Running") {
                    $VoraussetzungsStatus.WinRM = $true
                    $ErfolgreichePruefungen++
                    Write-Log -Nachricht "  [OK] WinRM konfiguriert und gestartet." -Level "ERFOLG"
                }
                else { throw "WinRM konnte nicht gestartet werden." }
            }
            catch {
                $VoraussetzungsStatus.WinRM = $false
                $FehlgeschlagenePruefungen++
                $KritischerFehler = $true
                Write-Log -Nachricht "  [FEHLER] WinRM-Konfiguration fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
            }
        }

        try {
            $TestWinRM = Test-WSMan -ComputerName localhost -ErrorAction Stop
            Write-Log -Nachricht "  -> WinRM lokaler Test: OK (Version: $($TestWinRM.ProductVersion))" -Level "INFO"
        }
        catch {
            Write-Log -Nachricht "  -> WinRM lokaler Test fehlgeschlagen." -Level "WARNUNG"
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        $KritischerFehler = $true
        Write-Log -Nachricht "  [FEHLER] WinRM-Pruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 9: Firewall-Regeln fuer WinRM
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe Firewall-Regeln fuer WinRM..." -Level "INFO"

    try {
        $WinRMHTTPRegel = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -ErrorAction SilentlyContinue

        if ($null -ne $WinRMHTTPRegel) {
            $AktiveRegeln = $WinRMHTTPRegel | Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Allow" }

            if ($AktiveRegeln.Count -gt 0) {
                $VoraussetzungsStatus.Firewall = $true
                $ErfolgreichePruefungen++
                Write-Log -Nachricht "  [OK] WinRM Firewall-Regel aktiv ($($AktiveRegeln.Count) Regel(n))" -Level "ERFOLG"
            }
            else {
                try {
                    $WinRMHTTPRegel | Set-NetFirewallRule -Enabled True -ErrorAction Stop
                    $VoraussetzungsStatus.Firewall = $true
                    $ErfolgreichePruefungen++
                    Write-Log -Nachricht "  [OK] WinRM Firewall-Regel aktiviert." -Level "ERFOLG"
                }
                catch {
                    $FehlgeschlagenePruefungen++
                    Write-Log -Nachricht "  [FEHLER] Firewall-Regel konnte nicht aktiviert werden." -Level "FEHLER"
                }
            }
        }
        else {
            try {
                New-NetFirewallRule -DisplayName "WinRM HTTP (SecureBoot-Pruefung)" `
                    -Direction Inbound -Protocol TCP -LocalPort 5985 `
                    -Action Allow -Profile Domain `
                    -Description "WinRM fuer Secure Boot Zertifikatspruefung" `
                    -ErrorAction Stop | Out-Null
                $VoraussetzungsStatus.Firewall = $true
                $ErfolgreichePruefungen++
                Write-Log -Nachricht "  [OK] WinRM Firewall-Regel erstellt (Port 5985, Domain)." -Level "ERFOLG"
            }
            catch {
                $FehlgeschlagenePruefungen++
                Write-Log -Nachricht "  [FEHLER] Firewall-Regel konnte nicht erstellt werden." -Level "FEHLER"
            }
        }

        try {
            $DefaultOutbound = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
            if ($null -ne $DefaultOutbound -and $DefaultOutbound.DefaultOutboundAction -eq "Block") {
                New-NetFirewallRule -DisplayName "WinRM Outbound (SecureBoot-Pruefung)" `
                    -Direction Outbound -Protocol TCP -RemotePort 5985 `
                    -Action Allow -Profile Domain -ErrorAction SilentlyContinue | Out-Null
                Write-Log -Nachricht "  -> Ausgehende Regel erstellt (Outbound blockiert)." -Level "INFO"
            }
        }
        catch { }
    }
    catch {
        $FehlgeschlagenePruefungen++
        Write-Log -Nachricht "  [FEHLER] Firewall-Pruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # PRUEFUNG 10: Netzwerkkonnektivitaet zum Domaenencontroller
    # -----------------------------------------------------------------------
    $PruefungNummer++
    Write-Log -Nachricht "[$PruefungNummer/$PruefungenGesamt] Pruefe Netzwerk zum Domaenencontroller..." -Level "INFO"

    try {
        if ($VoraussetzungsStatus.Domaenenmitglied -and $VoraussetzungsStatus.ADModul) {
            try {
                $DC = Get-ADDomainController -Discover -ErrorAction Stop

                # BUGFIX v2.1: ADPropertyValueCollection -> String
                [string]$DCName = $DC.HostName[0]

                Write-Log -Nachricht "  -> DC: $DCName (Standort: $($DC.Site))" -Level "INFO"

                $DCPing = Test-Connection -ComputerName $DCName -Count 2 -Quiet -ErrorAction SilentlyContinue
                if ($DCPing) {
                    $VoraussetzungsStatus.Netzwerkverbindung = $true
                    $ErfolgreichePruefungen++
                    Write-Log -Nachricht "  [OK] DC $DCName erreichbar." -Level "ERFOLG"

                    try {
                        $DNSTest = Resolve-DnsName -Name $DCName -ErrorAction Stop
                        Write-Log -Nachricht "  -> DNS: OK ($($DNSTest.IPAddress -join ', '))" -Level "INFO"
                    }
                    catch { Write-Log -Nachricht "  -> DNS-Aufloesung fehlgeschlagen." -Level "WARNUNG" }

                    try {
                        $LDAPTest = Test-NetConnection -ComputerName $DCName -Port 389 -WarningAction SilentlyContinue -ErrorAction Stop
                        Write-Log -Nachricht "  -> LDAP (389): $(if($LDAPTest.TcpTestSucceeded){'OK'}else{'FEHLGESCHLAGEN'})" -Level "INFO"
                    }
                    catch { Write-Log -Nachricht "  -> LDAP-Test uebersprungen." -Level "WARNUNG" }
                }
                else {
                    $VoraussetzungsStatus.Netzwerkverbindung = $false
                    $FehlgeschlagenePruefungen++
                    $KritischerFehler = $true
                    Write-Log -Nachricht "  [FEHLER] DC $DCName NICHT erreichbar!" -Level "FEHLER"
                }
            }
            catch {
                try {
                    $Domaenenname = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
                    $DomainPing = Test-Connection -ComputerName $Domaenenname -Count 2 -Quiet -ErrorAction SilentlyContinue
                    if ($DomainPing) {
                        $VoraussetzungsStatus.Netzwerkverbindung = $true
                        $ErfolgreichePruefungen++
                        Write-Log -Nachricht "  [OK] Domaene $Domaenenname erreichbar (Fallback)." -Level "ERFOLG"
                    }
                    else {
                        $VoraussetzungsStatus.Netzwerkverbindung = $false
                        $FehlgeschlagenePruefungen++
                        $KritischerFehler = $true
                        Write-Log -Nachricht "  [FEHLER] Domaene $Domaenenname NICHT erreichbar." -Level "FEHLER"
                    }
                }
                catch {
                    $FehlgeschlagenePruefungen++
                    Write-Log -Nachricht "  [FEHLER] Netzwerktest fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
                }
            }
        }
        else {
            $FehlgeschlagenePruefungen++
            Write-Log -Nachricht "  [UEBERSPRUNGEN] Netzwerktest (Domaene: $($VoraussetzungsStatus.Domaenenmitglied), AD: $($VoraussetzungsStatus.ADModul))" -Level "WARNUNG"
        }
    }
    catch {
        $FehlgeschlagenePruefungen++
        Write-Log -Nachricht "  [FEHLER] Netzwerkpruefung fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    }

    # -----------------------------------------------------------------------
    # ZUSAMMENFASSUNG
    # -----------------------------------------------------------------------
    Write-Log -Nachricht "" -Level "INFO"
    Write-Log -Nachricht "============================================================" -Level "PHASE"
    Write-Log -Nachricht "  ERGEBNIS DER VORAUSSETZUNGSPRUEFUNG                       " -Level "PHASE"
    Write-Log -Nachricht "============================================================" -Level "PHASE"
    Write-Log -Nachricht "" -Level "INFO"

    $StatusSymbol = @{ $true = "[OK]    "; $false = "[FEHLER]" }
    foreach ($Pruefung in $VoraussetzungsStatus.GetEnumerator() | Sort-Object Name) {
        $Symbol = $StatusSymbol[$Pruefung.Value]
        $Farbe  = if ($Pruefung.Value) { "ERFOLG" } else { "FEHLER" }
        Write-Log -Nachricht "  $Symbol $($Pruefung.Name)" -Level $Farbe
    }

    Write-Log -Nachricht "" -Level "INFO"
    Write-Log -Nachricht "Ergebnis: $ErfolgreichePruefungen von $PruefungenGesamt Pruefungen bestanden." -Level "INFO"

    if ($KritischerFehler) {
        Write-Log -Nachricht "" -Level "FEHLER"
        Write-Log -Nachricht "!!! KRITISCHE FEHLER GEFUNDEN !!!" -Level "FEHLER"

        if (-not $VoraussetzungsStatus.Administrator)      { Write-Log -Nachricht "  - Administratorrechte fehlen" -Level "FEHLER" }
        if (-not $VoraussetzungsStatus.PowerShellVersion)  { Write-Log -Nachricht "  - PowerShell-Version zu alt" -Level "FEHLER" }
        if (-not $VoraussetzungsStatus.ADModul)            { Write-Log -Nachricht "  - Active Directory Modul fehlt" -Level "FEHLER" }
        if (-not $VoraussetzungsStatus.Domaenenmitglied)   { Write-Log -Nachricht "  - Keine Domaenenmitgliedschaft" -Level "FEHLER" }
        if (-not $VoraussetzungsStatus.WinRM)              { Write-Log -Nachricht "  - WinRM nicht konfiguriert" -Level "FEHLER" }
        if (-not $VoraussetzungsStatus.Netzwerkverbindung) { Write-Log -Nachricht "  - DC nicht erreichbar" -Level "FEHLER" }

        Write-Log -Nachricht "" -Level "FEHLER"
        $Antwort = Read-Host "Trotz Fehler fortfahren? (J/N)"
        if ($Antwort -notin @("J", "j", "Ja", "ja", "Y", "y", "Yes", "yes")) {
            Write-Log -Nachricht "Skript auf Benutzerwunsch beendet." -Level "INFO"
            exit 1
        }
        else {
            Write-Log -Nachricht "Benutzer hat Fortsetzung bestaetigt." -Level "WARNUNG"
        }
    }
    else {
        Write-Log -Nachricht "" -Level "ERFOLG"
        Write-Log -Nachricht "Alle Voraussetzungen erfuellt! Starte Secure Boot Pruefung..." -Level "ERFOLG"
    }

    Write-Log -Nachricht "============================================================" -Level "INFO"
    return (-not $KritischerFehler)
}

# endregion PHASE 1
# ============================================================================

# ============================================================================
# region PHASE 2: HILFSFUNKTIONEN FUER SECURE BOOT PRUEFUNG
# ============================================================================

function Test-ComputerErreichbar {
    <#
    .SYNOPSIS
        Prueft ob ein Computer im Netzwerk erreichbar ist.
    .PARAMETER ComputerName
        Der Name des zu pruefenden Computers.
    .PARAMETER TimeoutMs
        Timeout in Millisekunden.
    .EXAMPLE
        Test-ComputerErreichbar -ComputerName "SERVER01" -TimeoutMs 2000
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 1000
    )

    try {
        $PingErgebnis = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $PingErgebnis
    }
    catch {
        return $false
    }
}

function Get-SecureBootStatus {
    <#
    .SYNOPSIS
        Prueft den Secure Boot- und Zertifikatsstatus auf einem Remote-Computer.
    .DESCRIPTION
        Dreistufige Erkennung des UEFI CA 2023 Zertifikatsstatus:
          Stufe 1: Registry UEFICA2023Status (REG_SZ unter Servicing)
          Stufe 2: Registry WindowsUEFICA2023Capable (REG_DWORD unter Servicing)
          Stufe 3: Direkte Pruefung der Secure Boot DB via Get-SecureBootUEFI
        Zusaetzlich: AvailableUpdates Bitmask-Analyse
    .PARAMETER ComputerName
        Der Name des zu pruefenden Computers.
    .EXAMPLE
        Get-SecureBootStatus -ComputerName "SERVER01"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        $RemoteErgebnis = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {

            $Ergebnis = [PSCustomObject]@{
                SecureBootAktiviert          = $null
                SecureBootUEFI               = $null
                UEFICA2023Status             = $null
                UEFICA2023StatusText         = "Nicht geprueft"
                UEFICA2023StatusRoh          = $null
                UEFICA2023Error              = $null
                UEFICA2023Erkennungsstufe    = "Keine"        # NEU: Zeigt welche Stufe den Status ermittelt hat
                ZertifikatInDB               = $null           # NEU: Direktes Ergebnis der DB-Pruefung
                BootManagerAktuell           = $null           # NEU: WindowsUEFICA2023Capable = 2
                AvailableUpdates             = $null           # NEU: Bitmask-Rohwert
                AvailableUpdatesText         = $null           # NEU: Klartext der ausstehenden Updates
                DBUpdateInstalliert          = $null
                KEKUpdateInstalliert         = $null
                BIOSVersion                  = $null
                BIOSDatum                    = $null
                BIOSHersteller               = $null
                TPMVorhanden                 = $null
                TPMVersion                   = $null
                UEFIModus                    = $null
                Betriebssystem               = $null
                OSVersion                    = $null
                OSBuild                      = $null
                LetzterNeustart              = $null
                Fehler                       = $null
            }

            try {
                # --- 1. Secure Boot Status aus Registry ---
                try {
                    $SecureBootReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction Stop
                    $Ergebnis.SecureBootAktiviert = [bool]$SecureBootReg.UEFISecureBootEnabled
                }
                catch {
                    $Ergebnis.SecureBootAktiviert = $false
                }

                # --- 2. Secure Boot via Cmdlet ---
                try {
                    $Ergebnis.SecureBootUEFI = Confirm-SecureBootUEFI -ErrorAction Stop
                }
                catch {
                    $Ergebnis.SecureBootUEFI = $false
                }

                # --- 3. UEFI CA 2023 Status - DREISTUFIGE ERKENNUNG ---
                # =============================================================
                # BUGFIX v2.2: Korrekter Pfad SecureBoot\Servicing, REG_SZ
                # BUGFIX v2.3: Dreistufige Erkennung:
                #   Stufe 1: UEFICA2023Status (REG_SZ) - primaerer Indikator
                #   Stufe 2: WindowsUEFICA2023Capable (REG_DWORD) - sekundaer
                #   Stufe 3: Direkte DB-Pruefung via Get-SecureBootUEFI db
                #
                # Hintergrund: Auf Server 2016 und aelteren Systemen kann es
                # vorkommen, dass UEFICA2023Status nicht existiert, das 2023
                # Zertifikat aber trotzdem in der Secure Boot DB vorhanden ist
                # (z.B. manuell installiert oder ueber anderen Mechanismus).
                # =============================================================

                [bool]$StatusErmittelt = $false

                # ---- STUFE 1: UEFICA2023Status (REG_SZ unter Servicing) ----
                try {
                    $ServicingPfad = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

                    if (Test-Path -Path $ServicingPfad) {
                        $UEFICA2023Reg = Get-ItemProperty -Path $ServicingPfad -Name "UEFICA2023Status" -ErrorAction Stop
                        [string]$StatusText = $UEFICA2023Reg.UEFICA2023Status

                        $Ergebnis.UEFICA2023StatusRoh = $StatusText
                        $Ergebnis.UEFICA2023Erkennungsstufe = "Stufe 1: UEFICA2023Status"

                        switch ($StatusText.Trim().ToLower()) {
                            "notstarted" {
                                $Ergebnis.UEFICA2023Status     = 0
                                $Ergebnis.UEFICA2023StatusText = "Nicht gestartet - Update erforderlich"
                                $StatusErmittelt = $true
                            }
                            "inprogress" {
                                $Ergebnis.UEFICA2023Status     = 1
                                $Ergebnis.UEFICA2023StatusText = "In Bearbeitung - Neustart erforderlich"
                                $StatusErmittelt = $true
                            }
                            "updated" {
                                $Ergebnis.UEFICA2023Status     = 2
                                $Ergebnis.UEFICA2023StatusText = "Aktualisiert - Bereit fuer 2026"
                                $StatusErmittelt = $true
                            }
                            default {
                                # Unbekannter Wert - weiter zu Stufe 2
                                $Ergebnis.UEFICA2023StatusRoh = "Unbekannt: '$StatusText'"
                            }
                        }

                        # Fehlercode auslesen wenn vorhanden
                        try {
                            $ErrorReg = Get-ItemProperty -Path $ServicingPfad -Name "UEFICA2023Error" -ErrorAction SilentlyContinue
                            if ($null -ne $ErrorReg -and $ErrorReg.UEFICA2023Error -ne 0) {
                                $Ergebnis.UEFICA2023Error = $ErrorReg.UEFICA2023Error
                                $Ergebnis.UEFICA2023StatusText += " | FEHLER: 0x$($ErrorReg.UEFICA2023Error.ToString('X'))"
                            }
                        }
                        catch { }
                    }
                }
                catch {
                    # UEFICA2023Status nicht vorhanden - weiter zu Stufe 2
                }

                # ---- STUFE 2: WindowsUEFICA2023Capable (REG_DWORD unter Servicing) ----
                if (-not $StatusErmittelt) {
                    try {
                        $ServicingPfad = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

                        if (Test-Path -Path $ServicingPfad) {
                            $CapableReg = Get-ItemProperty -Path $ServicingPfad -Name "WindowsUEFICA2023Capable" -ErrorAction Stop
                            [int]$CapableWert = $CapableReg.WindowsUEFICA2023Capable

                            switch ($CapableWert) {
                                0 {
                                    # Capable sagt "nicht in DB" - aber das kann veraltet sein!
                                    # Weiter zu Stufe 3 (direkte DB-Pruefung)
                                    $Ergebnis.UEFICA2023StatusRoh = "WindowsUEFICA2023Capable=0 (pruefe DB direkt)"
                                }
                                1 {
                                    $Ergebnis.UEFICA2023Status     = 2
                                    $Ergebnis.UEFICA2023StatusText = "Zertifikat in DB (Capable=1) - Bereit fuer 2026"
                                    $Ergebnis.UEFICA2023StatusRoh  = "WindowsUEFICA2023Capable=1"
                                    $Ergebnis.UEFICA2023Erkennungsstufe = "Stufe 2: WindowsUEFICA2023Capable"
                                    $Ergebnis.ZertifikatInDB       = $true
                                    $StatusErmittelt = $true
                                }
                                2 {
                                    $Ergebnis.UEFICA2023Status     = 3
                                    $Ergebnis.UEFICA2023StatusText = "Zertifikat in DB + 2023 Boot-Manager aktiv (Capable=2) - Vollstaendig"
                                    $Ergebnis.UEFICA2023StatusRoh  = "WindowsUEFICA2023Capable=2"
                                    $Ergebnis.UEFICA2023Erkennungsstufe = "Stufe 2: WindowsUEFICA2023Capable"
                                    $Ergebnis.ZertifikatInDB       = $true
                                    $Ergebnis.BootManagerAktuell   = $true
                                    $StatusErmittelt = $true
                                }
                                default {
                                    $Ergebnis.UEFICA2023StatusRoh = "WindowsUEFICA2023Capable=$CapableWert (unbekannt)"
                                }
                            }
                        }
                    }
                    catch {
                        # WindowsUEFICA2023Capable nicht vorhanden - weiter zu Stufe 3
                    }
                }

                # ---- STUFE 3: Direkte Pruefung der Secure Boot DB ----
                # Diese Stufe ist der zuverlaessigste Test, da sie die
                # tatsaechlichen UEFI-Variablen ausliest und nicht auf
                # Registry-Tracking-Werte angewiesen ist.
                if (-not $StatusErmittelt) {
                    try {
                        $DBInhalt = Get-SecureBootUEFI -Name db -ErrorAction Stop

                        if ($null -ne $DBInhalt -and $null -ne $DBInhalt.bytes) {
                            [string]$DBString = [System.Text.Encoding]::ASCII.GetString($DBInhalt.bytes)
                            [bool]$Cert2023Gefunden = $DBString -match "Windows UEFI CA 2023"

                            $Ergebnis.ZertifikatInDB = $Cert2023Gefunden
                            $Ergebnis.UEFICA2023Erkennungsstufe = "Stufe 3: Direkte DB-Pruefung (Get-SecureBootUEFI)"

                            if ($Cert2023Gefunden) {
                                $Ergebnis.UEFICA2023Status     = 2
                                $Ergebnis.UEFICA2023StatusText = "Zertifikat in DB vorhanden (direkte Pruefung) - Bereit fuer 2026"
                                $Ergebnis.UEFICA2023StatusRoh  = "DB-Scan: 'Windows UEFI CA 2023' GEFUNDEN"
                                $StatusErmittelt = $true
                            }
                            else {
                                $Ergebnis.UEFICA2023Status     = 0
                                $Ergebnis.UEFICA2023StatusText = "Zertifikat NICHT in DB (direkte Pruefung) - Update erforderlich"
                                $Ergebnis.UEFICA2023StatusRoh  = "DB-Scan: 'Windows UEFI CA 2023' NICHT gefunden"
                                $StatusErmittelt = $true
                            }
                        }
                        else {
                            $Ergebnis.UEFICA2023StatusRoh = "Get-SecureBootUEFI db: Keine Daten"
                        }
                    }
                    catch {
                        # Get-SecureBootUEFI nicht verfuegbar (z.B. Legacy BIOS)
                        $Ergebnis.UEFICA2023StatusRoh = "DB-Pruefung fehlgeschlagen: $($_.Exception.Message)"
                    }
                }

                # ---- Fallback wenn keine Stufe erfolgreich war ----
                if (-not $StatusErmittelt) {
                    $Ergebnis.UEFICA2023Status     = -99
                    $Ergebnis.UEFICA2023StatusText = "Status konnte ueber keine Erkennungsstufe ermittelt werden"
                    $Ergebnis.UEFICA2023Erkennungsstufe = "Keine Stufe erfolgreich"
                }

                # ---- AvailableUpdates Bitmask auslesen ----
                try {
                    $AvailReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue
                    if ($null -ne $AvailReg) {
                        [int]$AvailWert = $AvailReg.AvailableUpdates
                        $Ergebnis.AvailableUpdates = "0x$($AvailWert.ToString('X4'))"

                        if ($AvailWert -eq 0) {
                            $Ergebnis.AvailableUpdatesText = "Keine ausstehenden Updates"
                        }
                        else {
                            # Bitmask entschluesseln
                            [System.Collections.ArrayList]$AusstehendeUpdates = @()

                            # Bekannte Bits pruefen
                            if ($AvailWert -band 0x0004) { [void]$AusstehendeUpdates.Add("DB-Update (2023 CA Zertifikat)") }
                            if ($AvailWert -band 0x0040) { [void]$AusstehendeUpdates.Add("Neuer Boot-Manager") }
                            if ($AvailWert -band 0x0100) { [void]$AusstehendeUpdates.Add("DBX-Update (Sperrliste)") }
                            if ($AvailWert -band 0x0800) { [void]$AusstehendeUpdates.Add("KEK-Update") }
                            if ($AvailWert -band 0x1000) { [void]$AusstehendeUpdates.Add("2023 Boot-Manager-Update") }
                            if ($AvailWert -band 0x4000) { [void]$AusstehendeUpdates.Add("2023 Boot-Manager Final") }

                            if ($AusstehendeUpdates.Count -gt 0) {
                                $Ergebnis.AvailableUpdatesText = $AusstehendeUpdates -join " | "
                            }
                            else {
                                $Ergebnis.AvailableUpdatesText = "Unbekannte Bits: 0x$($AvailWert.ToString('X4'))"
                            }
                        }
                    }
                }
                catch { }

                # ---- Ergaenzende Info: Wenn Zertifikat in DB aber noch Updates ausstehen ----
                if ($Ergebnis.ZertifikatInDB -eq $true -and $null -ne $Ergebnis.AvailableUpdates -and $Ergebnis.AvailableUpdates -ne "0x0000") {
                    $Ergebnis.UEFICA2023StatusText += " | Ausstehend: $($Ergebnis.AvailableUpdatesText)"
                }

                # --- 4. DB und KEK Zertifikate ---
                try {
                    $DBCerts = Get-SecureBootUEFI -Name db -ErrorAction SilentlyContinue
                    $Ergebnis.DBUpdateInstalliert = ($null -ne $DBCerts)
                    $KEKCerts = Get-SecureBootUEFI -Name KEK -ErrorAction SilentlyContinue
                    $Ergebnis.KEKUpdateInstalliert = ($null -ne $KEKCerts)
                }
                catch {
                    $Ergebnis.DBUpdateInstalliert = "Pruefung nicht moeglich"
                    $Ergebnis.KEKUpdateInstalliert = "Pruefung nicht moeglich"
                }

                # --- 5. BIOS-Informationen ---
                try {
                    $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
                    $Ergebnis.BIOSVersion    = $BIOS.SMBIOSBIOSVersion
                    $Ergebnis.BIOSDatum      = $BIOS.ReleaseDate
                    $Ergebnis.BIOSHersteller = $BIOS.Manufacturer
                }
                catch {
                    $Ergebnis.BIOSVersion = "Nicht ermittelbar"
                }

                # --- 6. UEFI-Modus ---
                try {
                    $SBState = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction SilentlyContinue
                    $Ergebnis.UEFIModus = if ($null -ne $SBState) { "UEFI" } else { "Legacy BIOS" }
                }
                catch {
                    $Ergebnis.UEFIModus = "Nicht ermittelbar"
                }

                # --- 7. TPM-Informationen ---
                try {
                    $TPM = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
                    $Ergebnis.TPMVorhanden = $true
                    $Ergebnis.TPMVersion   = $TPM.SpecVersion
                }
                catch {
                    $Ergebnis.TPMVorhanden = $false
                    $Ergebnis.TPMVersion   = "Nicht verfuegbar"
                }

                # --- 8. Betriebssystem ---
                try {
                    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                    $Ergebnis.Betriebssystem  = $OS.Caption
                    $Ergebnis.OSVersion       = $OS.Version
                    $Ergebnis.OSBuild         = $OS.BuildNumber
                    $Ergebnis.LetzterNeustart = $OS.LastBootUpTime
                }
                catch {
                    $Ergebnis.Betriebssystem = "Nicht ermittelbar"
                }
            }
            catch {
                $Ergebnis.Fehler = $_.Exception.Message
            }

            return $Ergebnis
        }

        return $RemoteErgebnis
    }
    catch {
        Write-Log -Nachricht "WinRM-Fehler bei '$ComputerName': $($_.Exception.Message)" -Level "FEHLER" -InKonsole $false

        return [PSCustomObject]@{
            SecureBootAktiviert          = "Verbindungsfehler"
            SecureBootUEFI               = "Verbindungsfehler"
            UEFICA2023Status             = -99
            UEFICA2023StatusText         = "WinRM-Verbindung fehlgeschlagen"
            UEFICA2023StatusRoh          = "Verbindungsfehler"
            UEFICA2023Error              = $null
            UEFICA2023Erkennungsstufe    = "Keine (Verbindungsfehler)"
            ZertifikatInDB               = "Unbekannt"
            BootManagerAktuell           = "Unbekannt"
            AvailableUpdates             = "Unbekannt"
            AvailableUpdatesText         = "Verbindungsfehler"
            DBUpdateInstalliert          = "Unbekannt"
            KEKUpdateInstalliert         = "Unbekannt"
            BIOSVersion                  = "Unbekannt"
            BIOSDatum                    = "Unbekannt"
            BIOSHersteller               = "Unbekannt"
            TPMVorhanden                 = "Unbekannt"
            TPMVersion                   = "Unbekannt"
            UEFIModus                    = "Unbekannt"
            Betriebssystem               = "Unbekannt"
            OSVersion                    = "Unbekannt"
            OSBuild                      = "Unbekannt"
            LetzterNeustart              = "Unbekannt"
            Fehler                       = $_.Exception.Message
        }
    }
}

function New-HtmlReport {
    <#
    .SYNOPSIS
        Erstellt einen formatierten HTML-Report der Pruefergebnisse.
    .PARAMETER Ergebnisse
        Die Ergebnis-ArrayList.
    .PARAMETER AusgabePfad
        Der Dateipfad fuer die HTML-Datei.
    .EXAMPLE
        New-HtmlReport -Ergebnisse $ErgebnisListe -AusgabePfad "C:\ExchangeMigrationLog\Report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Ergebnisse,

        [Parameter(Mandatory = $true)]
        [string]$AusgabePfad
    )

    try {
        $HtmlKopf = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Secure Boot Zertifikatsstatus - Unternehmensbericht</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #003366; border-bottom: 3px solid #003366; padding-bottom: 10px; }
        h3 { margin-top: 0; }
        .zusammenfassung { background: #e8f4fd; border-left: 5px solid #003366; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .kritisch { background: #f8d7da; border-left: 5px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .voraussetzungen { background: #d4edda; border-left: 5px solid #28a745; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .hinweis { background: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin-top: 15px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th { background: #003366; color: white; padding: 12px 8px; text-align: left; font-size: 13px; position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid #ddd; font-size: 12px; }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #e8f4fd; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-kritisch { color: #dc3545; font-weight: bold; }
        .status-warnung { color: #856404; font-weight: bold; }
        .status-unbekannt { color: #6c757d; font-style: italic; }
        .footer { margin-top: 30px; font-size: 11px; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
    </style>
</head>
<body>
    <h1>&#128274; Secure Boot Zertifikatsstatus - Unternehmensbericht</h1>
    <p><strong>Erstellt:</strong> $(Get-Date -Format "dd.MM.yyyy HH:mm:ss") | <strong>Ablauf alte Zertifikate:</strong> Juni 2026 | <strong>Version:</strong> 2.3</p>

    <div class="voraussetzungen">
        <h3>Voraussetzungspruefung</h3>
        <p>Alle Voraussetzungen wurden automatisch geprueft und ggf. nachinstalliert.</p>
    </div>

    <div class="zusammenfassung">
        <h3>Zusammenfassung</h3>
        <ul>
            <li>Gepruefte Computer: <strong>$GesamtComputer</strong></li>
            <li>Erreichbar: <strong>$ErreichbareComputer</strong> | Nicht erreichbar: <strong>$NichtErreichbareComputer</strong></li>
            <li>Secure Boot aktiv: <strong>$SecureBootAktiv</strong> | Inaktiv: <strong>$SecureBootInaktiv</strong></li>
            <li>Zertifikat 2023 aktualisiert: <strong class="status-ok">$ZertifikatAktualisiert</strong></li>
            <li>Zertifikat NICHT aktualisiert: <strong class="status-kritisch">$ZertifikatNichtAktualisiert</strong></li>
            <li>Fehler: <strong>$FehlerAnzahl</strong></li>
        </ul>
    </div>

    <div class="hinweis">
        <h3>&#128269; Erkennungsmethodik (v2.3)</h3>
        <p>Der Zertifikatsstatus wird dreistufig ermittelt:</p>
        <ol>
            <li><strong>Stufe 1:</strong> Registry UEFICA2023Status (REG_SZ unter SecureBoot\Servicing)</li>
            <li><strong>Stufe 2:</strong> Registry WindowsUEFICA2023Capable (REG_DWORD unter SecureBoot\Servicing)</li>
            <li><strong>Stufe 3:</strong> Direkte Pruefung der Secure Boot DB via Get-SecureBootUEFI (zuverlaessigster Test)</li>
        </ol>
    </div>
"@

        if ($ZertifikatNichtAktualisiert -gt 0) {
            $HtmlKopf += @"
    <div class="kritisch">
        <h3>&#9888; Handlungsbedarf</h3>
        <p><strong>$ZertifikatNichtAktualisiert Computer</strong> benoetigen das Secure Boot 2023 Zertifikatsupdate vor Juni 2026.</p>
        <p>Empfohlene Aktion: <code>reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f</code></p>
    </div>
"@
        }

        $HtmlTabelle = $Ergebnisse | ConvertTo-Html -Fragment -Property `
            ComputerName, Erreichbar, SecureBootAktiviert, UEFIModus, UEFICA2023StatusText, `
            UEFICA2023Erkennungsstufe, UEFICA2023StatusRoh, ZertifikatInDB, AvailableUpdates, AvailableUpdatesText, `
            BIOSHersteller, BIOSVersion, BIOSDatum, TPMVorhanden, TPMVersion, `
            Betriebssystem, OSVersion, LetzterNeustart, Bewertung, Fehler

        # Status-Hervorhebung
        $HtmlTabelle = $HtmlTabelle -replace '<td>Bereit fuer 2026</td>', '<td class="status-ok">&#10004; Bereit fuer 2026</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Update erforderlich</td>', '<td class="status-kritisch">&#10008; Update erforderlich</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Nicht erreichbar</td>', '<td class="status-unbekannt">Nicht erreichbar</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Aktualisiert - Bereit fuer 2026</td>', '<td class="status-ok">&#10004; Aktualisiert - Bereit fuer 2026</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Nicht gestartet - Update erforderlich</td>', '<td class="status-kritisch">&#10008; Nicht gestartet - Update erforderlich</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>In Bearbeitung - Neustart erforderlich</td>', '<td class="status-warnung">&#9888; In Bearbeitung - Neustart erforderlich</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Zertifikat in DB vorhanden \(direkte Pruefung\) - Bereit fuer 2026</td>', '<td class="status-ok">&#10004; Zertifikat in DB (direkte Pruefung) - Bereit fuer 2026</td>'
        $HtmlTabelle = $HtmlTabelle -replace '<td>Zertifikat NICHT in DB \(direkte Pruefung\) - Update erforderlich</td>', '<td class="status-kritisch">&#10008; Zertifikat NICHT in DB - Update erforderlich</td>'

        $HtmlFuss = @"
    <div class="footer">
        <p>Generiert von: Check-SecureBootCertStatus.ps1 v2.3 | Log: $LogDateiPfad</p>
        <p>Erkennungspfade: Servicing\UEFICA2023Status (REG_SZ) &rarr; Servicing\WindowsUEFICA2023Capable (REG_DWORD) &rarr; Get-SecureBootUEFI db (Direkt)</p>
        <p>Empfohlener AvailableUpdates-Wert fuer vollstaendige Aktualisierung: <code>0x5944</code> (Quelle: Microsoft KB5068202)</p>
    </div>
</body></html>
"@

        ($HtmlKopf + $HtmlTabelle + $HtmlFuss) | Out-File -FilePath $AusgabePfad -Encoding UTF8 -Force
        Write-Log -Nachricht "HTML-Report erstellt: $AusgabePfad" -Level "ERFOLG"
    }
    catch {
        Write-Log -Nachricht "Fehler beim HTML-Report: $($_.Exception.Message)" -Level "FEHLER"
    }
}

# endregion PHASE 2: HILFSFUNKTIONEN
# ============================================================================

# ============================================================================
# region HAUPTPROGRAMM
# ============================================================================

# --- Log-Verzeichnis sicherstellen ---
try {
    if (-not (Test-Path -Path $LogVerzeichnis)) {
        New-Item -Path $LogVerzeichnis -ItemType Directory -Force | Out-Null
    }
}
catch {
    Write-Error "KRITISCH: Log-Verzeichnis konnte nicht erstellt werden: $($_.Exception.Message)"
    exit 1
}

# --- Skript-Header ---
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "################################################################" -Level "INFO"
Write-Log -Nachricht "#  SECURE BOOT ZERTIFIKATSPRUEFUNG v2.3                        #" -Level "INFO"
Write-Log -Nachricht "#  Mit dreistufiger Zertifikatserkennung                       #" -Level "INFO"
Write-Log -Nachricht "#  Datum: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')                              #" -Level "INFO"
Write-Log -Nachricht "################################################################" -Level "INFO"

# =============================================
# PHASE 1: Voraussetzungspruefung
# =============================================
if (-not $SkipVoraussetzungspruefung) {
    $VoraussetzungenOK = Test-AlleVoraussetzungen
    if (-not $VoraussetzungenOK) {
        Write-Log -Nachricht "Voraussetzungspruefung: Kritische Fehler. Skript faehrt mit Einschraenkungen fort." -Level "WARNUNG"
    }
}
else {
    Write-Log -Nachricht "Voraussetzungspruefung uebersprungen (-SkipVoraussetzungspruefung)." -Level "WARNUNG"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Log -Nachricht "KRITISCH: Active Directory Modul nicht ladbar!" -Level "FEHLER"
        exit 1
    }
}

# =============================================
# PHASE 2: Computer aus AD abfragen
# =============================================
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "============================================================" -Level "PHASE"
Write-Log -Nachricht "  PHASE 2: ACTIVE DIRECTORY ABFRAGE                         " -Level "PHASE"
Write-Log -Nachricht "============================================================" -Level "PHASE"

try {
    Write-Log -Nachricht "Frage Computer-Objekte aus dem Active Directory ab..." -Level "INFO"

    $ADParameter = @{
        Filter     = "OperatingSystem -like 'Windows*'"
        Properties = @("Name", "OperatingSystem", "OperatingSystemVersion", "Enabled",
                       "LastLogonDate", "DistinguishedName", "IPv4Address", "Description")
    }

    if (-not [string]::IsNullOrWhiteSpace($ADSearchBase)) {
        $ADParameter.Add("SearchBase", $ADSearchBase)
        Write-Log -Nachricht "Suche eingeschraenkt auf: $ADSearchBase" -Level "INFO"
    }

    $AlleComputer = Get-ADComputer @ADParameter | Sort-Object Name

    if ($NurAktiveComputer) {
        $AlleComputer = $AlleComputer | Where-Object { $_.Enabled -eq $true }
        Write-Log -Nachricht "Filter: Nur aktivierte Computer" -Level "INFO"
    }

    $GesamtComputer = ($AlleComputer | Measure-Object).Count
    Write-Log -Nachricht "Gefundene Computer: $GesamtComputer" -Level "ERFOLG"

    if ($GesamtComputer -eq 0) {
        Write-Log -Nachricht "Keine Computer gefunden. Skript wird beendet." -Level "WARNUNG"
        exit 0
    }
}
catch {
    Write-Log -Nachricht "AD-Abfrage fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
    exit 1
}

# =============================================
# PHASE 3: Secure Boot Pruefung durchfuehren
# =============================================
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "============================================================" -Level "PHASE"
Write-Log -Nachricht "  PHASE 3: SECURE BOOT PRUEFUNG ($GesamtComputer Computer)  " -Level "PHASE"
Write-Log -Nachricht "  Dreistufige Erkennung: Registry > Capable > DB-Scan       " -Level "PHASE"
Write-Log -Nachricht "============================================================" -Level "PHASE"

[int]$Zaehler = 0

foreach ($Computer in $AlleComputer) {
    $Zaehler++
    [string]$ComputerName = $Computer.Name
    [int]$Prozent = [math]::Round(($Zaehler / $GesamtComputer) * 100, 0)

    Write-Progress -Activity "Secure Boot Zertifikatspruefung" `
                   -Status "Pruefe: $ComputerName ($Zaehler/$GesamtComputer)" `
                   -PercentComplete $Prozent

    # Ergebnis-Objekt
    $ComputerErgebnis = [PSCustomObject]@{
        ComputerName                 = $ComputerName
        ADDistinguishedName          = $Computer.DistinguishedName
        ADBetriebssystem             = $Computer.OperatingSystem
        ADIPAdresse                  = $Computer.IPv4Address
        ADLetztesLogon               = $Computer.LastLogonDate
        Erreichbar                   = $false
        SecureBootAktiviert          = "Unbekannt"
        SecureBootUEFI               = "Unbekannt"
        UEFIModus                    = "Unbekannt"
        UEFICA2023Status             = "Unbekannt"
        UEFICA2023StatusText         = "Nicht geprueft"
        UEFICA2023StatusRoh          = "Nicht geprueft"
        UEFICA2023Erkennungsstufe    = "Keine"
        ZertifikatInDB               = "Nicht geprueft"
        BootManagerAktuell           = "Nicht geprueft"
        AvailableUpdates             = "Nicht geprueft"
        AvailableUpdatesText         = "Nicht geprueft"
        DBUpdateInstalliert          = "Unbekannt"
        KEKUpdateInstalliert         = "Unbekannt"
        BIOSVersion                  = "Unbekannt"
        BIOSDatum                    = "Unbekannt"
        BIOSHersteller               = "Unbekannt"
        TPMVorhanden                 = "Unbekannt"
        TPMVersion                   = "Unbekannt"
        Betriebssystem               = "Unbekannt"
        OSVersion                    = "Unbekannt"
        LetzterNeustart              = "Unbekannt"
        Bewertung                    = "Nicht geprueft"
        Fehler                       = ""
    }

    try {
        # Erreichbarkeit pruefen
        $IstErreichbar = Test-ComputerErreichbar -ComputerName $ComputerName -TimeoutMs $PingTimeoutMs

        if (-not $IstErreichbar) {
            $NichtErreichbareComputer++
            $ComputerErgebnis.Bewertung = "Nicht erreichbar"
            $ComputerErgebnis.Fehler    = "Ping fehlgeschlagen"
            [void]$ErgebnisListe.Add($ComputerErgebnis)
            continue
        }

        $ErreichbareComputer++
        $ComputerErgebnis.Erreichbar = $true

        # Secure Boot Status abfragen
        $StatusErgebnis = Get-SecureBootStatus -ComputerName $ComputerName

        if ($null -ne $StatusErgebnis) {
            # Ergebnisse uebertragen
            $ComputerErgebnis.SecureBootAktiviert       = $StatusErgebnis.SecureBootAktiviert
            $ComputerErgebnis.SecureBootUEFI            = $StatusErgebnis.SecureBootUEFI
            $ComputerErgebnis.UEFIModus                 = $StatusErgebnis.UEFIModus
            $ComputerErgebnis.UEFICA2023Status          = $StatusErgebnis.UEFICA2023Status
            $ComputerErgebnis.UEFICA2023StatusText      = $StatusErgebnis.UEFICA2023StatusText
            $ComputerErgebnis.UEFICA2023StatusRoh       = $StatusErgebnis.UEFICA2023StatusRoh
            $ComputerErgebnis.UEFICA2023Erkennungsstufe = $StatusErgebnis.UEFICA2023Erkennungsstufe
            $ComputerErgebnis.ZertifikatInDB            = $StatusErgebnis.ZertifikatInDB
            $ComputerErgebnis.BootManagerAktuell        = $StatusErgebnis.BootManagerAktuell
            $ComputerErgebnis.AvailableUpdates          = $StatusErgebnis.AvailableUpdates
            $ComputerErgebnis.AvailableUpdatesText      = $StatusErgebnis.AvailableUpdatesText
            $ComputerErgebnis.DBUpdateInstalliert       = $StatusErgebnis.DBUpdateInstalliert
            $ComputerErgebnis.KEKUpdateInstalliert      = $StatusErgebnis.KEKUpdateInstalliert
            $ComputerErgebnis.BIOSVersion               = $StatusErgebnis.BIOSVersion
            $ComputerErgebnis.BIOSDatum                 = $StatusErgebnis.BIOSDatum
            $ComputerErgebnis.BIOSHersteller            = $StatusErgebnis.BIOSHersteller
            $ComputerErgebnis.TPMVorhanden              = $StatusErgebnis.TPMVorhanden
            $ComputerErgebnis.TPMVersion                = $StatusErgebnis.TPMVersion
            $ComputerErgebnis.Betriebssystem            = $StatusErgebnis.Betriebssystem
            $ComputerErgebnis.OSVersion                 = $StatusErgebnis.OSVersion
            $ComputerErgebnis.LetzterNeustart           = $StatusErgebnis.LetzterNeustart
            $ComputerErgebnis.Fehler                    = $StatusErgebnis.Fehler

            # Bewertung
            if ($StatusErgebnis.SecureBootAktiviert -eq $true) {
                $SecureBootAktiv++

                if ($StatusErgebnis.UEFICA2023Status -ge 2) {
                    $ZertifikatAktualisiert++
                    $ComputerErgebnis.Bewertung = "Bereit fuer 2026"

                    # Pruefen ob noch AvailableUpdates ausstehen
                    if ($null -ne $StatusErgebnis.AvailableUpdates -and $StatusErgebnis.AvailableUpdates -ne "0x0000" -and $StatusErgebnis.AvailableUpdates -ne $null) {
                        $ComputerErgebnis.Bewertung += " | Noch ausstehend: $($StatusErgebnis.AvailableUpdatesText)"
                    }
                }
                elseif ($StatusErgebnis.UEFICA2023Status -eq 1) {
                    $ZertifikatNichtAktualisiert++
                    $ComputerErgebnis.Bewertung = "Teilweise aktualisiert - Neustart noetig"
                }
                elseif ($StatusErgebnis.UEFICA2023Status -eq 0) {
                    $ZertifikatNichtAktualisiert++
                    $ComputerErgebnis.Bewertung = "Update erforderlich"
                }
                else {
                    $ZertifikatNichtAktualisiert++
                    $ComputerErgebnis.Bewertung = "Status unklar - manuelle Pruefung noetig"
                }

                # BIOS-Datum pruefen
                if ($null -ne $StatusErgebnis.BIOSDatum) {
                    try {
                        $BiosDatumObj = [datetime]$StatusErgebnis.BIOSDatum
                        if ($BiosDatumObj.Year -lt $BiosMindestJahr) {
                            $ComputerErgebnis.Bewertung += " | BIOS-Update empfohlen"
                        }
                    }
                    catch { }
                }
            }
            else {
                $SecureBootInaktiv++
                if ($StatusErgebnis.UEFIModus -eq "Legacy BIOS") {
                    $ComputerErgebnis.Bewertung = "Legacy BIOS - Secure Boot nicht verfuegbar"
                }
                else {
                    $ComputerErgebnis.Bewertung = "Secure Boot DEAKTIVIERT"
                }
            }

            Write-Log -Nachricht "  [$Zaehler/$GesamtComputer] $ComputerName : $($ComputerErgebnis.Bewertung) [Erkennung: $($StatusErgebnis.UEFICA2023Erkennungsstufe)]" -Level "INFO" -InKonsole $false
        }
        else {
            $FehlerAnzahl++
            $ComputerErgebnis.Bewertung = "Pruefung fehlgeschlagen"
        }
    }
    catch {
        $FehlerAnzahl++
        $ComputerErgebnis.Bewertung = "Fehler bei Pruefung"
        $ComputerErgebnis.Fehler    = $_.Exception.Message
        Write-Log -Nachricht "  FEHLER bei $ComputerName : $($_.Exception.Message)" -Level "FEHLER" -InKonsole $false
    }

    [void]$ErgebnisListe.Add($ComputerErgebnis)
}

Write-Progress -Activity "Secure Boot Zertifikatspruefung" -Completed

# =============================================
# PHASE 4: Ergebnisse exportieren
# =============================================
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "============================================================" -Level "PHASE"
Write-Log -Nachricht "  PHASE 4: ERGEBNISSE EXPORTIEREN                           " -Level "PHASE"
Write-Log -Nachricht "============================================================" -Level "PHASE"

# CSV-Export
try {
    $ErgebnisListe | Export-Csv -Path $CsvExportPfad -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Log -Nachricht "CSV-Report: $CsvExportPfad" -Level "ERFOLG"
}
catch {
    Write-Log -Nachricht "CSV-Export fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
}

# HTML-Report
try {
    New-HtmlReport -Ergebnisse $ErgebnisListe -AusgabePfad $HtmlExportPfad
}
catch {
    Write-Log -Nachricht "HTML-Report fehlgeschlagen: $($_.Exception.Message)" -Level "FEHLER"
}

# =============================================
# ZUSAMMENFASSUNG
# =============================================
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "################################################################" -Level "PHASE"
Write-Log -Nachricht "#                   ZUSAMMENFASSUNG                            #" -Level "PHASE"
Write-Log -Nachricht "################################################################" -Level "PHASE"
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "Gepruefte Computer:                $GesamtComputer" -Level "INFO"
Write-Log -Nachricht "Erreichbar:                        $ErreichbareComputer" -Level "INFO"
Write-Log -Nachricht "Nicht erreichbar:                  $NichtErreichbareComputer" -Level "WARNUNG"
Write-Log -Nachricht "------------------------------------------------------------" -Level "INFO"
Write-Log -Nachricht "Secure Boot AKTIV:                 $SecureBootAktiv" -Level "ERFOLG"
Write-Log -Nachricht "Secure Boot INAKTIV:               $SecureBootInaktiv" -Level "WARNUNG"
Write-Log -Nachricht "------------------------------------------------------------" -Level "INFO"
Write-Log -Nachricht "Zertifikat 2023 AKTUALISIERT:      $ZertifikatAktualisiert" -Level "ERFOLG"
Write-Log -Nachricht "Zertifikat 2023 NICHT aktualisiert: $ZertifikatNichtAktualisiert" -Level "FEHLER"
Write-Log -Nachricht "Fehler:                            $FehlerAnzahl" -Level "FEHLER"
Write-Log -Nachricht "------------------------------------------------------------" -Level "INFO"
Write-Log -Nachricht "CSV-Report:  $CsvExportPfad" -Level "INFO"
Write-Log -Nachricht "HTML-Report: $HtmlExportPfad" -Level "INFO"
Write-Log -Nachricht "Log-Datei:   $LogDateiPfad" -Level "INFO"
Write-Log -Nachricht "------------------------------------------------------------" -Level "INFO"

# Erkennungsstufen-Statistik
Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "Erkennungsstufen-Statistik:" -Level "INFO"
$ErgebnisListe | Where-Object { $_.Erreichbar -eq $true } |
    Group-Object -Property UEFICA2023Erkennungsstufe |
    ForEach-Object {
        Write-Log -Nachricht "  $($_.Name): $($_.Count) Computer" -Level "INFO"
    }

if ($ZertifikatNichtAktualisiert -gt 0) {
    Write-Log -Nachricht "" -Level "FEHLER"
    Write-Log -Nachricht "!!! $ZertifikatNichtAktualisiert Computer benoetigen das Secure Boot Zertifikatsupdate !!!" -Level "FEHLER"
    Write-Log -Nachricht "Die alten Zertifikate laufen ab Juni 2026 aus!" -Level "FEHLER"
    Write-Log -Nachricht "" -Level "FEHLER"
    Write-Log -Nachricht "Empfohlene Aktion fuer betroffene Computer:" -Level "FEHLER"
    Write-Log -Nachricht "  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f" -Level "INFO"
    Write-Log -Nachricht "  (Quelle: Microsoft KB5068202)" -Level "INFO"
    Write-Log -Nachricht "" -Level "FEHLER"
    Write-Log -Nachricht "Betroffene Computer:" -Level "FEHLER"

    $BetroffeneComputer = $ErgebnisListe | Where-Object {
        $_.Bewertung -like "*Update erforderlich*" -or
        $_.Bewertung -like "*Teilweise aktualisiert*" -or
        $_.Bewertung -like "*Status unklar*"
    }

    foreach ($Betroffen in $BetroffeneComputer) {
        Write-Log -Nachricht "  -> $($Betroffen.ComputerName) : $($Betroffen.Bewertung) [Erkennung: $($Betroffen.UEFICA2023Erkennungsstufe)] (Roh: $($Betroffen.UEFICA2023StatusRoh))" -Level "FEHLER"
    }
}

Write-Log -Nachricht "" -Level "INFO"
Write-Log -Nachricht "Skript beendet: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -Level "INFO"

# endregion HAUPTPROGRAMM
# ============================================================================
