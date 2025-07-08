# AD-Guardian.ps1
<#+
.SYNOPSIS
    Ultimate PowerShell AD Security Tool - AD-Guardian
.DESCRIPTION
    Modular, extensible tool for auditing and remediating Active Directory security issues.
    Loads configuration from config.json and modules from /modules.
#>

# Load configuration
$ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
if (!(Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found: $ConfigPath"
    exit 1
}
$Config = Get-Content $ConfigPath | ConvertFrom-Json

# Ensure Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory module is not installed. Please install RSAT-AD-PowerShell."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# Ensure report output path exists
if (-not (Test-Path $Config.reportOutputPath)) {
    try {
        New-Item -Path $Config.reportOutputPath -ItemType Directory -Force | Out-Null
    } catch {
        Write-Error "Failed to create report output directory: $($_.Exception.Message)"
        exit 1
    }
}

# Discover modules
$AuditModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'modules/audits'
$RemediationModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'modules/remediation'
if (Test-Path $AuditModulesPath) {
    Get-ChildItem -Path $AuditModulesPath -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}
if (Test-Path $RemediationModulesPath) {
    Get-ChildItem -Path $RemediationModulesPath -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

function Show-Menu {
    Clear-Host
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "      AD-Guardian Main Menu      " -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1. Run Full Audit (Read-Only)"
    Write-Host "2. Run Specific Audit Modules"
    Write-Host "3. Run Audit with Interactive Remediation"
    Write-Host "4. Exit"
}

function Write-HTMLReport {
    param(
        [Parameter(Mandatory)]
        $Results
    )
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $domain = (Get-ADDomain).DNSRoot
    $reportPath = Join-Path -Path $Config.reportOutputPath -ChildPath "AD-Guardian-Report-$timestamp.html"

    $dashboard = $Results | Group-Object RiskLevel | ForEach-Object {
        "<span class='risk-$($_.Name.ToLower())'><b>$($_.Count) $($_.Name)</b> risks found</span>"
    } | Out-String

    $html = @"
<html>
<head>
<title>AD-Guardian Security Report</title>
<style>
body { font-family:Segoe UI,Arial,sans-serif; background:#f8f8f8; color:#222; }
h1 { color:#2a4d7f; }
.dashboard { background:#e8eef7; padding:10px; margin-bottom:20px; border-radius:8px; }
.risk-critical { color:#b30000; font-weight:bold; }
.risk-high { color:#e67300; font-weight:bold; }
.risk-medium { color:#e6b800; font-weight:bold; }
.risk-low { color:#228b22; font-weight:bold; }
table { border-collapse:collapse; width:100%; margin-bottom:30px; }
th,td { border:1px solid #ccc; padding:6px 10px; }
th { background:#e8eef7; cursor:pointer; }
tr:nth-child(even) { background:#f2f2f2; }
details { margin-bottom:10px; }
summary { font-weight:bold; cursor:pointer; }
</style>
</head>
<body>
<h1>AD-Guardian Security Report</h1>
<div class='dashboard'>
<b>Domain:</b> $domain<br>
<b>Generated:</b> $(Get-Date)<br>
$dashboard
</div>
"@

    $modules = $Results | Group-Object Finding
    foreach ($risk in @('Critical','High','Medium','Low','Info','Error')) {
        $section = $Results | Where-Object { $_.RiskLevel -eq $risk }
        if ($section) {
            $html += "<details open><summary class='risk-$($risk.ToLower())'>$risk Findings</summary>"
            $html += "<table><tr><th>Status</th><th>Finding</th><th>Details</th></tr>"
            foreach ($item in $section) {
                $html += "<tr><td>$($item.Status)</td><td>$($item.Finding)</td><td><pre>$(($item.Details | Out-String).Trim())</pre></td></tr>"
            }
            $html += "</table></details>"
        }
    }
    $html += "</body></html>"
    $html | Set-Content -Path $reportPath -Encoding UTF8
    Write-Host "HTML report generated: $reportPath" -ForegroundColor Green
}

function Run-FullAudit {
    $allResults = @()
    $allResults += Get-PrivilegedGroupMembers -Config $Config
    $allResults += Get-StaleAccounts -Config $Config
    $allResults += Get-NonExpiringPasswords -Config $Config
    $allResults += Get-KerberoastableAccounts -Config $Config
    $allResults += Get-ASREPBroastableAccounts -Config $Config
    $allResults += Get-LapsCompliance -Config $Config
    $allResults += Get-AdminSDHolderPermissions -Config $Config
    $allResults += Get-UnconstrainedDelegation -Config $Config

    # Dashboard summary
    $summary = $allResults | Group-Object RiskLevel | ForEach-Object {
        "$($_.Count) $($_.Name) risks found"
    }
    Write-Host "\n==== Dashboard Summary ====" -ForegroundColor Cyan
    $summary | ForEach-Object { Write-Host $_ }
    Write-Host "==========================\n" -ForegroundColor Cyan

    # Detailed findings
    foreach ($result in $allResults) {
        Write-Host ("[{0}] {1} - {2}" -f $result.RiskLevel, $result.Status, $result.Finding)
        if ($result.Status -eq 'Error') {
            Write-Host ("  Details: {0}" -f $result.Details) -ForegroundColor Red
        } else {
            Write-Host ("  Details: {0}" -f ($result.Details | Out-String).Trim())
        }
    }
    Write-HTMLReport -Results $allResults
}

function Get-AuditModuleList {
    return @(
        @{ Name = 'Get-PrivilegedGroupMembers';      Display = 'Privileged Group Members' },
        @{ Name = 'Get-StaleAccounts';               Display = 'Stale Accounts' },
        @{ Name = 'Get-NonExpiringPasswords';        Display = 'Non-Expiring Passwords' },
        @{ Name = 'Get-KerberoastableAccounts';      Display = 'Kerberoastable Accounts' },
        @{ Name = 'Get-ASREPBroastableAccounts';     Display = 'AS-REP Roastable Accounts' },
        @{ Name = 'Get-LapsCompliance';              Display = 'LAPS Compliance' },
        @{ Name = 'Get-AdminSDHolderPermissions';    Display = 'AdminSDHolder Permissions' },
        @{ Name = 'Get-UnconstrainedDelegation';     Display = 'Unconstrained Delegation' }
    )
}

function Run-SpecificAudit {
    $modules = Get-AuditModuleList
    Write-Host "\nAvailable Audit Modules:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $modules.Count; $i++) {
        Write-Host ("{0}. {1}" -f ($i+1), $modules[$i].Display)
    }
    $sel = Read-Host "Select a module to run (1-$($modules.Count)) or press Enter to cancel"
    if (-not $sel) {
        Write-Host "Cancelled."
        return
    }
    if ($sel -notmatch '^[0-9]+$') {
        Write-Host "Invalid input. Please enter a number between 1 and $($modules.Count)." -ForegroundColor Red
        return
    }
    $sel = [int]$sel
    if ($sel -lt 1 -or $sel -gt $modules.Count) {
        Write-Host "Invalid selection. Please choose a number between 1 and $($modules.Count)." -ForegroundColor Red
        return
    }
    $mod = $modules[$sel-1]
    $func = Get-Command $mod.Name -ErrorAction SilentlyContinue
    if ($null -eq $func) {
        Write-Host "Module function not found: $($mod.Name)" -ForegroundColor Red
        return
    }
    $results = & $mod.Name -Config $Config
    foreach ($result in $results) {
        Write-Host ("[{0}] {1} - {2}" -f $result.RiskLevel, $result.Status, $result.Finding)
        Write-Host ("  Details: {0}" -f ($result.Details | Out-String).Trim())
    }
}

function Run-AuditWithRemediation {
    $allResults = @()
    $allResults += Get-PrivilegedGroupMembers -Config $Config
    $allResults += Get-StaleAccounts -Config $Config
    $allResults += Get-NonExpiringPasswords -Config $Config
    $allResults += Get-KerberoastableAccounts -Config $Config
    $allResults += Get-ASREPBroastableAccounts -Config $Config
    $allResults += Get-LapsCompliance -Config $Config
    $allResults += Get-AdminSDHolderPermissions -Config $Config
    $allResults += Get-UnconstrainedDelegation -Config $Config

    foreach ($result in $allResults) {
        Write-Host ("[{0}] {1} - {2}" -f $result.RiskLevel, $result.Status, $result.Finding)
        Write-Host ("  Details: {0}" -f ($result.Details | Out-String).Trim())
        # Offer remediation for certain findings
        if ($result.Status -eq 'Fail') {
            switch ($result.Finding) {
                { $_ -like '*in group*' } {
                    $rem = Read-Host "Remediate by removing user from group? (Y/N)"
                    if ($rem -eq 'Y') {
                        Remove-UserFromPrivilegedGroup -SamAccountName $result.Details.SamAccountName -GroupName ($result.Finding -replace '.*in group ', '')
                    }
                }
                { $_ -like '*is stale*' } {
                    $rem = Read-Host "Remediate by disabling account? (Y/N)"
                    if ($rem -eq 'Y') {
                        Disable-StaleAccount -SamAccountName $result.Details.SamAccountName -ObjectClass $result.Details.ObjectClass
                    }
                }
                { $_ -like '*Password Never Expires*' } {
                    $rem = Read-Host "Remediate by disabling 'Password Never Expires'? (Y/N)"
                    if ($rem -eq 'Y') {
                        Fix-InsecurePasswordSetting -SamAccountName $result.Details.SamAccountName
                    }
                }
                { $_ -like '*AS-REP roastable*' } {
                    $rem = Read-Host "Remediate by enabling Kerberos preauthentication? (Y/N)"
                    if ($rem -eq 'Y') {
                        Fix-ASREPBroastable -SamAccountName $result.Details.SamAccountName
                    }
                }
            }
        }
    }
}

function Main {
    do {
        Show-Menu
        $choice = Read-Host "Select an option (1-4)"
        switch ($choice) {
            '1' {
                Write-Host "[INFO] Running full audit..."
                Run-FullAudit
            }
            '2' {
                Write-Host "[INFO] Listing available audit modules..."
                Run-SpecificAudit
            }
            '3' {
                Write-Host "[INFO] Running audit with interactive remediation..."
                Run-AuditWithRemediation
            }
            '4' {
                Write-Host "Exiting. Goodbye!" -ForegroundColor Green
                exit 0
            }
            Default {
                Write-Host "Invalid selection. Please choose 1-4." -ForegroundColor Red
            }
        }
        if ($choice -ne '4') { Pause }
    } while ($true)
}

Main
exit 0 