<#
.SYNOPSIS
Analysiert Entra ID Sign-In Logs für Conditional Access Policies

.DESCRIPTION
Zeigt Anmeldungen, die von CA-Policies blockiert wurden oder würden (Report-Only)

.NOTES
Installation (als Admin in PowerShell):
Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber

Benötigte Berechtigungen: AuditLog.Read.All, Directory.Read.All, Policy.Read.All
#>

#Requires -Version 5.1

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

try {
    # Prüfen ob Module verfügbar sind
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Fehler: Microsoft.Graph Module nicht installiert" -ForegroundColor Red
        Write-Host "`nInstallation (als Admin):" -ForegroundColor Yellow
        Write-Host "Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber"
        exit
    }

    # Account-Auswahl
    Write-Host "========== ACCOUNT AUSWAHL ==========" -ForegroundColor Cyan
    Write-Host "Mit welchem Account möchten Sie sich anmelden?`n"
    
    $accountChoice = Read-Host "Bitte UPN eingeben (z.B. admin@tenant.onmicrosoft.com) oder ENTER für interaktive Auswahl"
    
    # Verbindung zu Microsoft Graph
    Write-Host "`nVerbinde zu Microsoft Graph..." -ForegroundColor Cyan
    
    if ([string]::IsNullOrWhiteSpace($accountChoice)) {
        # Interaktive Auswahl - Browser öffnet sich
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All" -NoWelcome
    } else {
        # Mit spezifischem Account
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All" -AccountId $accountChoice -NoWelcome
    }
    
    # Verbindungsinfo anzeigen
    $context = Get-MgContext
    Write-Host "`nAngemeldet als: " -NoNewline -ForegroundColor Green
    Write-Host $context.Account -ForegroundColor White
    Write-Host "Tenant: " -NoNewline -ForegroundColor Green
    Write-Host "$($context.TenantId)" -ForegroundColor White
    
    $confirm = Read-Host "`nIst dies der korrekte Tenant? (j/y/n)"
    if ($confirm -ne "j" -and $confirm -ne "y") {
        Write-Host "Abgebrochen. Bitte Script erneut starten." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        exit
    }

    # Anzahl Tage abfragen
    $daysBack = Read-Host "`nWie viele Tage zurück sollen die Logs ausgewertet werden?"
    $startDate = (Get-Date).AddDays(-[int]$daysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Alle Conditional Access Policies abrufen
    Write-Host "`nLade Conditional Access Policies..." -ForegroundColor Cyan
    $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method GET
    
    # Report-Only und Aktive Policies filtern
    $relevantPolicies = $allPolicies.value | Where-Object { 
        $_.state -eq "enabledForReportingButNotEnforced" -or $_.state -eq "enabled" 
    } | Select-Object @{Name='Id';Expression={$_.id}}, 
                       @{Name='DisplayName';Expression={$_.displayName}}, 
                       @{Name='State';Expression={$_.state}}

    if ($relevantPolicies.Count -eq 0) {
        Write-Host "Keine aktiven oder Report-Only Policies gefunden." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        exit
    }

    Write-Host "`nVerfügbare Conditional Access Policies:" -ForegroundColor Green
    for ($i = 0; $i -lt $relevantPolicies.Count; $i++) {
        $status = if ($relevantPolicies[$i].State -eq "enabled") { "[AKTIV]" } else { "[REPORT-ONLY]" }
        $color = if ($relevantPolicies[$i].State -eq "enabled") { "Red" } else { "Yellow" }
        Write-Host "[$i] " -NoNewline
        Write-Host "$status " -ForegroundColor $color -NoNewline
        Write-Host "$($relevantPolicies[$i].DisplayName)"
    }

    # Policy-Auswahl
    $selection = Read-Host "`nWelche Policy auswerten? (Nummer eingeben oder 'alle' für alle Policies)"

    if ($selection -eq "alle") {
        $selectedPolicies = $relevantPolicies
    } else {
        $selectedPolicies = @($relevantPolicies[[int]$selection])
    }

    # Auswertung für jede Policy
    Write-Host "`n========== AUSWERTUNG ==========" -ForegroundColor Cyan

    $allExportData = @()

    foreach ($policy in $selectedPolicies) {
        $policyStatus = if ($policy.State -eq "enabled") { "AKTIV" } else { "REPORT-ONLY" }
        $statusColor = if ($policy.State -eq "enabled") { "Red" } else { "Yellow" }
        
        Write-Host "`nPolicy: $($policy.DisplayName)" -ForegroundColor White
        Write-Host "Status: " -NoNewline
        Write-Host "$policyStatus" -ForegroundColor $statusColor
        Write-Host "Policy ID: $($policy.Id)" -ForegroundColor Gray
        
        # Logs mit Filter auf diese Policy laden
        Write-Host "Lade Logs für diese Policy..." -ForegroundColor Cyan
        
        $signInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate" -All | 
            Where-Object { 
                $_.AppliedConditionalAccessPolicies | Where-Object { 
                    $_.Id -eq $policy.Id -and (
                        $_.Result -eq "reportOnlyFailure" -or 
                        $_.Result -eq "failure"
                    )
                }
            }

        if ($signInLogs.Count -eq 0) {
            Write-Host "Keine blockierten Verbindungen für diese Policy." -ForegroundColor Yellow
            continue
        }

        # Blockierte vs Report-Only aufteilen
        $actualBlocks = $signInLogs | Where-Object {
            $_.AppliedConditionalAccessPolicies | Where-Object {
                $_.Id -eq $policy.Id -and $_.Result -eq "failure"
            }
        }

        $reportOnlyBlocks = $signInLogs | Where-Object {
            $_.AppliedConditionalAccessPolicies | Where-Object {
                $_.Id -eq $policy.Id -and $_.Result -eq "reportOnlyFailure"
            }
        }

        Write-Host "`n=== ÜBERSICHT ===" -ForegroundColor White
        if ($actualBlocks.Count -gt 0) {
            Write-Host "Tatsächlich blockiert: $($actualBlocks.Count)" -ForegroundColor Red
        }
        if ($reportOnlyBlocks.Count -gt 0) {
            Write-Host "Würde blockiert werden (Report-Only): $($reportOnlyBlocks.Count)" -ForegroundColor Yellow
        }
        Write-Host "Gesamt: $($signInLogs.Count)" -ForegroundColor White

        # Top Benutzer
        $userBreakdown = $signInLogs | Group-Object UserPrincipalName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        Write-Host "`nTop 10 betroffene Benutzer:"
        foreach ($user in $userBreakdown) {
            Write-Host "  - $($user.Name): $($user.Count) Anmeldungen"
        }
        
        # Top Apps
        $appBreakdown = $signInLogs | Group-Object AppDisplayName | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        Write-Host "`nTop 10 betroffene Apps:"
        foreach ($app in $appBreakdown) {
            Write-Host "  - $($app.Name): $($app.Count) Anmeldungen"
        }
        
        # Länder
        $locationBreakdown = $signInLogs.Location | 
            Where-Object { $_ } | 
            Group-Object CountryOrRegion | 
            Sort-Object Count -Descending
        
        if ($locationBreakdown) {
            Write-Host "`nBetroffene Länder:"
            foreach ($loc in $locationBreakdown) {
                Write-Host "  - $($loc.Name): $($loc.Count) Anmeldungen"
            }
        }

        # Daten für Export sammeln
        foreach ($login in $signInLogs) {
            $caPolicy = $login.AppliedConditionalAccessPolicies | 
                Where-Object { $_.Id -eq $policy.Id }
            
            $blockType = if ($caPolicy.Result -eq "failure") { "Tatsächlich blockiert" } else { "Würde blockiert werden" }
            
            $allExportData += [PSCustomObject]@{
                Timestamp = $login.CreatedDateTime
                User = $login.UserPrincipalName
                UserDisplayName = $login.UserDisplayName
                App = $login.AppDisplayName
                PolicyName = $policy.DisplayName
                PolicyState = $policyStatus
                PolicyId = $policy.Id
                BlockType = $blockType
                Result = $caPolicy.Result
                GrantControls = ($caPolicy.GrantControls -join "; ")
                Country = $login.Location.CountryOrRegion
                City = $login.Location.City
                IPAddress = $login.IpAddress
                DeviceDetail = $login.DeviceDetail.DisplayName
                Status = $login.Status.ErrorCode
            }
        }
        
        Write-Host "`n" + ("-" * 50)
    }

    # Letzte 50 Einträge ausgeben
    if ($allExportData.Count -gt 0) {
        Write-Host "`n========== LETZTE 50 EINTRÄGE ==========" -ForegroundColor Cyan
        
        $last50 = $allExportData | Sort-Object Timestamp -Descending | Select-Object -First 50
        
        foreach ($entry in $last50) {
            $blockColor = if ($entry.BlockType -eq "Tatsächlich blockiert") { "Red" } else { "Yellow" }
            
            Write-Host "`n[$($entry.Timestamp)]" -ForegroundColor Gray
            Write-Host "  Benutzer: $($entry.User)" -ForegroundColor White
            Write-Host "  App: $($entry.App)" -ForegroundColor White
            Write-Host "  Policy: $($entry.PolicyName) [$($entry.PolicyState)]" -ForegroundColor White
            Write-Host "  Status: " -NoNewline
            Write-Host "$($entry.BlockType)" -ForegroundColor $blockColor
            Write-Host "  Location: $($entry.City), $($entry.Country) ($($entry.IPAddress))" -ForegroundColor Gray
            if ($entry.DeviceDetail) {
                Write-Host "  Gerät: $($entry.DeviceDetail)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 50)
        Write-Host "Angezeigte Einträge: $($last50.Count) von $($allExportData.Count) gesamt" -ForegroundColor Cyan
    }

    # Export-Option
    if ($allExportData.Count -gt 0) {
        $export = Read-Host "`nErgebnisse als CSV exportieren? (j/y/n)"
        if ($export -eq "j" -or $export -eq "y") {
            $exportPath = Read-Host "Pfad für CSV-Export (z.B. C:\Temp\ca-report.csv)"
            
            $allExportData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            Write-Host "Export abgeschlossen: $exportPath" -ForegroundColor Green
        }
    }

    Disconnect-MgGraph | Out-Null
    Write-Host "`nFertig." -ForegroundColor Green

} catch {
    Write-Host "Fehler: $_" -ForegroundColor Red
    if (Get-MgContext) {
        Disconnect-MgGraph | Out-Null
    }
    exit 1
}
