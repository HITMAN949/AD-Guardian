
$ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
if (!(Test-Path $ConfigPath)) {
    Write-Host "Configuration file not found. Creating a sample 'config.json' in the script directory." -ForegroundColor Yellow
    $sampleConfig = @{
        reportOutputPath          = ".\Reports"
        staleAccountThresholdDays = 90
        privilegedGroups          = @(
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins"
        )
        exclusions                = @{
            nonExpiringPasswords = @(
                "krbtgt"
            )
        }
        adminSdHolderDefaults     = @(
            "BUILTIN\Administrators",
            "BUILTIN\Account Operators",
            "BUILTIN\Print Operators",
            "BUILTIN\Server Operators",
            "NT AUTHORITY\SYSTEM",
            "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS",
            "NT AUTHORITY\Authenticated Users"
        )
    }
    $sampleConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "Sample 'config.json' created. Please review it and run the script again."
    exit 0
}

# Load configuration from the external JSON file
$Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

# Ensure Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory module is not installed. Please install the RSAT-AD-PowerShell feature."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# Ensure report output path exists
if (-not (Test-Path $Config.reportOutputPath)) {
    try {
        New-Item -Path $Config.reportOutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to create report output directory: $($_.Exception.Message)"
        exit 1
    }
}

#endregion

#region Audit Modules

function Get-ADGStaleAccountsAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    
    Write-Verbose "Checking for stale user accounts..."
    try {
        $staleTimespan = New-TimeSpan -Days $Config.staleAccountThresholdDays
        # Use Search-ADAccount as it's designed specifically for this task and is more reliable.
        $staleAccounts = Search-ADAccount -AccountInactive -TimeSpan $staleTimespan -UsersOnly -ResultPageSize 2000 | Get-ADUser -Properties LastLogonTimeStamp, SamAccountName
        
        if (!$staleAccounts) {
            return [PSCustomObject]@{
                RiskLevel = 'Info'
                Status    = 'Pass'
                Finding   = 'No stale user accounts found.'
            }
        }

        # Use foreach as a pipeline to generate output efficiently
        foreach ($account in $staleAccounts) {
            [PSCustomObject]@{
                RiskLevel              = 'Medium'
                Status                 = 'Fail'
                Finding                = "User account '$($account.SamAccountName)' is stale (inactive for over $($Config.staleAccountThresholdDays) days)."
                Details                = @{
                    LastLogon = if ($account.LastLogonTimeStamp) { [datetime]::FromFileTime($account.LastLogonTimeStamp) } else { 'Never' }
                    DN        = $account.DistinguishedName
                }
                RemediationDescription = "Disable user account '$($account.SamAccountName)'."
                RemediationScriptBlock = {
                    param($target)
                    Disable-ADAccount -Identity $target
                    Write-Host "Account '$($target.SamAccountName)' has been disabled." -ForegroundColor Green
                }
                RemediationTarget      = $account
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error searching for stale accounts.'; Details = $_.Exception.Message }
    }
}

function Get-ADGNonExpiringPasswordsAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking for accounts with non-expiring passwords..."
    try {
        $excludedUsers = $Config.exclusions.nonExpiringPasswords
        # The filter string must use double quotes for PowerShell to expand `$true`.
        $users = Get-ADUser -Filter "PasswordNeverExpires -eq `$true -and Enabled -eq `$true" -Properties SamAccountName | Where-Object { $excludedUsers -notcontains $_.SamAccountName }

        if (!$users) {
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'No non-excluded users found with non-expiring passwords.' }
        }

        foreach ($user in $users) {
            [PSCustomObject]@{
                RiskLevel              = 'High'
                Status                 = 'Fail'
                Finding                = "User '$($user.SamAccountName)' has 'Password Never Expires' enabled."
                Details                = @{ DistinguishedName = $user.DistinguishedName }
                RemediationDescription = "Disable 'Password Never Expires' for user '$($user.SamAccountName)'."
                RemediationScriptBlock = {
                    param($target)
                    Set-ADUser -Identity $target -PasswordNeverExpires $false
                    Write-Host "Updated user '$($target.SamAccountName)' to require password expiration." -ForegroundColor Green
                }
                RemediationTarget      = $user
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error checking for non-expiring passwords.'; Details = $_.Exception.Message }
    }
}

function Get-ADGAsRepRoastableAccountsAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking for AS-REP Roastable accounts..."
    try {
        # The filter string must use double quotes for PowerShell to expand `$true`.
        $users = Get-ADUser -Filter "DoesNotRequirePreAuth -eq `$true -and Enabled -eq `$true" -Properties SamAccountName

        if (!$users) {
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'No AS-REP roastable accounts found.' }
        }

        foreach ($user in $users) {
            [PSCustomObject]@{
                RiskLevel              = 'Critical'
                Status                 = 'Fail'
                Finding                = "User '$($user.SamAccountName)' is vulnerable to AS-REP Roasting."
                Details                = @{ DistinguishedName = $user.DistinguishedName }
                RemediationDescription = "Enable 'Kerberos preauthentication required' for user '$($user.SamAccountName)'."
                RemediationScriptBlock = {
                    param($target)
                    Set-ADUser -Identity $target -DoesNotRequirePreAuth $false
                    Write-Host "Fixed AS-REP Roasting vulnerability for '$($target.SamAccountName)'." -ForegroundColor Green
                }
                RemediationTarget      = $user
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error checking for AS-REP Roastable accounts.'; Details = $_.Exception.Message }
    }
}

function Get-ADGKerberoastableAccountsAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking for Kerberoastable accounts..."
    try {
        # The krbtgt account is a computer account but Get-ADUser can find it. Exclude it explicitly.
        $users = Get-ADUser -Filter 'ServicePrincipalName -like "*" -and Enabled -eq $true' -Properties SamAccountName, ServicePrincipalName | Where-Object { $_.SamAccountName -ne "krbtgt" }

        if (!$users) {
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'No user accounts vulnerable to Kerberoasting found.' }
        }

        foreach ($user in $users) {
            [PSCustomObject]@{
                RiskLevel              = 'Critical'
                Status                 = 'Fail'
                Finding                = "User '$($user.SamAccountName)' is vulnerable to Kerberoasting."
                Details                = @{ SPNs = $user.ServicePrincipalName -join ", " }
                RemediationDescription = "Manual remediation required. Review if '$($user.SamAccountName)' needs an SPN. If not, remove it. If so, ensure a long, complex password is set or use a Group Managed Service Account (gMSA)."
                RemediationScriptBlock = $null # No safe automatic remediation
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error checking for Kerberoastable accounts.'; Details = $_.Exception.Message }
    }
}

function Get-ADGPrivilegedGroupMembersAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking privileged group memberships..."
    # Use a variable to collect all findings efficiently.
    $allFindings = foreach ($groupName in $Config.privilegedGroups) {
        try {
            # Filter for users and computers, ignore nested groups in this check.
            $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop | Where-Object { $_.objectClass -in 'user', 'computer' }
            if (!$members) { continue }
            
            foreach ($member in $members) {
                [PSCustomObject]@{
                    RiskLevel              = 'High'
                    Status                 = 'Fail'
                    Finding                = "Account '$($member.SamAccountName)' is a member of the privileged group '$groupName'."
                    Details                = @{
                        MemberDN  = $member.DistinguishedName
                        GroupName = $groupName
                    }
                    RemediationDescription = "Remove account '$($member.SamAccountName)' from group '$groupName'."
                    RemediationScriptBlock = {
                        param($target)
                        Remove-ADGroupMember -Identity $target.Group -Members $target.Member -Confirm:$false
                        Write-Host "Removed '$($target.Member.SamAccountName)' from '$($target.Group)'." -ForegroundColor Green
                    }
                    RemediationTarget      = [PSCustomObject]@{
                        Member = $member
                        Group  = $groupName
                    }
                }
            }
        }
        catch {
            # This catch handles the case where a configured group name doesn't exist.
            [PSCustomObject]@{
                RiskLevel = 'Warning'
                Status    = 'Warning'
                Finding   = "Could not find privileged group '$groupName'. Please check your config.json file."
                Details   = $_.Exception.Message
            }
        }
    }
    
    if (!$allFindings) {
        return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'No direct user/computer members found in specified privileged groups.' }
    }
    else {
        return $allFindings
    }
}

function Get-ADGLapsComplianceAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking for LAPS compliance..."
    # This check uses the 'ms-Mcs-AdmPwd' attribute from the legacy Microsoft LAPS.
    # For modern, built-in Windows LAPS, check for 'msLAPS-Password'.
    try {
        if (-not (Get-Module -ListAvailable -Name "LAPS")) {
            Write-Verbose "LAPS PowerShell module not found. Skipping LAPS compliance check."
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Skipped'; Finding = 'LAPS PowerShell module not found. Skipping check.' }
        }

        $nonCompliantComputers = Get-ADComputer -Filter "Enabled -eq `$true" -Properties 'ms-Mcs-AdmPwd' | Where-Object { -not $_.'ms-Mcs-AdmPwd' }
        
        if (!$nonCompliantComputers) {
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'All enabled computers appear to be LAPS compliant (have the LAPS password attribute populated).' }
        }

        foreach ($computer in $nonCompliantComputers) {
            [PSCustomObject]@{
                RiskLevel              = 'Medium'
                Status                 = 'Fail'
                Finding                = "Computer '$($computer.Name)' is not LAPS compliant (missing password)."
                Details                = @{ DistinguishedName = $computer.DistinguishedName }
                RemediationDescription = "Manual remediation required. Investigate why LAPS is not applying to this computer."
                RemediationScriptBlock = $null
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error checking LAPS compliance.'; Details = $_.Exception.Message }
    }
}

function Get-ADGAdminSdHolderPermissionsAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Config
    )
    Write-Verbose "Checking AdminSDHolder permissions..."
    try {
        $rootDSE = Get-ADRootDSE
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($rootDSE.defaultNamingContext)"
        $acl = Get-Acl "AD:$adminSDHolderDN"
        
        # Use the configurable list of default principals from config.json
        $defaultPrincipals = $Config.adminSdHolderDefaults
        
        $unexpectedPermissions = $acl.Access | Where-Object { $_.IdentityReference.Value -notin $defaultPrincipals }

        if (!$unexpectedPermissions) {
            return [PSCustomObject]@{ RiskLevel = 'Info'; Status = 'Pass'; Finding = 'No unexpected permissions found on AdminSDHolder.' }
        }

        foreach ($ace in $unexpectedPermissions) {
            [PSCustomObject]@{
                RiskLevel              = 'High'
                Status                 = 'Fail'
                Finding                = "Unexpected principal '$($ace.IdentityReference)' has permissions on AdminSDHolder."
                Details                = @{
                    Rights              = $ace.ActiveDirectoryRights
                    AccessControlType   = $ace.AccessControlType
                    IsInherited         = $ace.IsInherited
                    InheritanceType     = $ace.InheritanceType
                    PropagationFlags    = $ace.PropagationFlags
                }
                RemediationDescription = "Manual investigation required. Unexpected changes to AdminSDHolder are high-risk. Review and remove if not explicitly required."
                RemediationScriptBlock = $null
            }
        }
    }
    catch {
        [PSCustomObject]@{ RiskLevel = 'Error'; Status = 'Error'; Finding = 'Error checking AdminSDHolder permissions.'; Details = $_.Exception.Message }
    }
}

#endregion

#region Core Functions

function Get-AvailableAuditModules {
    [CmdletBinding()]
    param()
    
    $auditFunctions = Get-Command -CommandType Function -Name 'Get-ADG*Audit'
    $modules = foreach ($func in $auditFunctions) {
        # Create a more readable display name from the function name
        $displayName = $func.Name -replace '^Get-ADG', '' -replace 'Audit$'
        $displayName = ($displayName -split '(?=[A-Z])') -join ' '
        [PSCustomObject]@{
            Name        = $func.Name
            Display     = $displayName.Trim()
            CommandInfo = $func
        }
    }
    return $modules | Sort-Object Display
}

function Run-Audits {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$ModulesToRun
    )
    
    $allResults = @()
    Write-Host "`n⚙️ Running $($ModulesToRun.Count) audit module(s)..." -ForegroundColor Yellow
    foreach ($module in $ModulesToRun) {
        Write-Host " -> Executing: $($module.Display)" -ForegroundColor Gray
        try {
            # Execute the audit function and pass the configuration to it
            $results = & $module.CommandInfo.ScriptBlock -Config $Config -Verbose:$false
            if ($null -ne $results) {
                # Add a property to each result object indicating which module found it
                $resultsWithSource = $results | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name 'SourceModule' -Value $module.Display -PassThru
                }
                $allResults += $resultsWithSource
            }
        }
        catch {
            $allResults += [PSCustomObject]@{
                RiskLevel    = 'Error'
                Status       = 'Execution Error'
                SourceModule = $module.Display
                Finding      = "Failed to run module $($module.Name)"
                Details      = $_.Exception.Message
            }
        }
    }
    return $allResults
}

function Show-Menu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "🛡️      AD-Guardian Main Menu      🛡️" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1. Run Full Audit (Read-Only)"
    Write-Host "2. Run Specific Audit Modules (Read-Only)"
    Write-Host "3. Run Full Audit with Interactive Remediation"
    Write-Host "4. Exit"
    Write-Host "===============================" -ForegroundColor Cyan
}

function Write-ConsoleOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results
    )
    
    # --- Dashboard ---
    Write-Host "`n==== Dashboard Summary ====" -ForegroundColor Cyan
    $summary = $Results | Group-Object RiskLevel | Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low', 'Info', 'Warning', 'Error').IndexOf($_.Name) } }
    if (!$summary) {
        Write-Host "✅ No findings to report." -ForegroundColor Green
    }
    else {
        foreach ($group in $summary) {
            $color = switch ($group.Name) {
                'Critical' { 'Red' }
                'High'     { 'Magenta' }
                'Medium'   { 'Yellow' }
                'Warning'  { 'DarkYellow' }
                'Info'     { 'Green' }
                default    { 'White' }
            }
            Write-Host ("{0} {1} finding(s)" -f $group.Count, $group.Name) -ForegroundColor $color
        }
    }
    Write-Host "==========================`n" -ForegroundColor Cyan

    # --- Detailed Findings ---
    # Group by the module that found the issue for better readability
    $groupedResults = $Results | Where-Object { $_.Status -ne 'Pass' } | Group-Object SourceModule
    foreach ($group in $groupedResults) {
        Write-Host "--- Audit Module: $($group.Name) ---" -ForegroundColor White
        foreach ($result in $group.Group) {
            $color = switch ($result.RiskLevel) {
                'Critical' { 'Red' }
                'High'     { 'Magenta' }
                'Medium'   { 'Yellow' }
                'Warning'  { 'DarkYellow' }
                default    { 'Gray' }
            }
            Write-Host ("[{0}] {1}" -f $result.RiskLevel.ToUpper(), $result.Finding) -ForegroundColor $color
            if ($result.Details) {
                # Format hashtable details nicely for console output
                $detailsString = ($result.Details | Format-List | Out-String).Trim()
                Write-Host ("  Details:`n{0}" -f $detailsString)
            }
            Write-Host "" # Newline for spacing
        }
    }
}

#endregion

#region Menu-driven Actions

function Start-FullAudit {
    [CmdletBinding()]
    param()
    
    $availableModules = Get-AvailableAuditModules
    if (!$availableModules) { Write-Warning "No audit functions (Get-ADG*Audit) found."; return }
    $allResults = Run-Audits -ModulesToRun $availableModules
    Write-ConsoleOutput -Results $allResults
    Write-HTMLReport -Results $allResults
}

function Start-SpecificAudit {
    [CmdletBinding()]
    param()
    
    $availableModules = Get-AvailableAuditModules
    if (!$availableModules) { Write-Warning "No audit functions found."; return }
    
    Write-Host "`nAvailable Audit Modules:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $availableModules.Count; $i++) {
        Write-Host ("{0,2}. {1}" -f ($i + 1), $availableModules[$i].Display)
    }
    
    try {
        $selection = Read-Host "`nSelect a module to run by number (1-$($availableModules.Count))"
        if (($selection -match '^\d+$') -and ([int]$selection -ge 1 -and [int]$selection -le $availableModules.Count)) {
            $selectedModule = $availableModules[[int]$selection - 1]
            $results = Run-Audits -ModulesToRun @($selectedModule)
            Write-ConsoleOutput -Results $results
        }
        else {
            Write-Warning "Invalid selection."
        }
    }
    catch {
        Write-Warning "Invalid input. Please enter a number."
    }
}

function Start-AuditWithRemediation {
    [CmdletBinding()]
    param()
    
    $availableModules = Get-AvailableAuditModules
    if (!$availableModules) { Write-Warning "No audit functions found."; return }
    
    # Run all audits first
    $allResults = Run-Audits -ModulesToRun $availableModules
    Write-ConsoleOutput -Results $allResults
    Write-HTMLReport -Results $allResults # Also generate a pre-remediation report
    
    # Filter for findings that have a remediation script block
    $remediationTargets = $allResults | Where-Object { $_.Status -eq 'Fail' -and $null -ne $_.RemediationScriptBlock }
    
    if (!$remediationTargets) {
        Write-Host "`n✅ No findings with available automatic remediation actions." -ForegroundColor Green
        return
    }

    Write-Host "`n==== Interactive Remediation ====" -ForegroundColor Yellow
    Write-Warning "You are about to make changes to your Active Directory environment."
    
    foreach ($result in $remediationTargets) {
        Write-Host ("`nFinding: {0}" -f $result.Finding) -ForegroundColor Yellow
        Write-Host ("Action: {0}" -f $result.RemediationDescription) -ForegroundColor Cyan
        
        $choice = Read-Host "Apply this remediation? (y/n)"
        if ($choice -eq 'y') {
            try {
                # Invoke the scriptblock, passing the target object as a parameter.
                & $result.RemediationScriptBlock $result.RemediationTarget
            }
            catch {
                Write-Error "Failed to apply remediation: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host " -> Remediation skipped by user." -ForegroundColor Gray
        }
    }
    Write-Host "`nRemediation session complete." -ForegroundColor Green
}

#endregion

#region HTML Report

function ConvertTo-SafeHtml {
    param($string)
    return $string.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Write-HTMLReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $domain = (Get-ADDomain).DNSRoot
    $reportPath = Join-Path -Path $Config.reportOutputPath -ChildPath "AD-Guardian-Report-$domain-$timestamp.html"
    
    $dashboardItems = $Results | Group-Object RiskLevel | ForEach-Object {
        "<span class='risk-$($_.Name.ToLower())'><b>$($_.Count) $($_.Name)</b></span>"
    }
    $dashboard = $dashboardItems -join " "
    
    $htmlHeader = @"
<html>
<head>
    <title>AD-Guardian Security Report</title>
    <style>
        body { font-family: 'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif; background-color: #f8f9fa; color: #212529; margin: 20px; }
        h1, h2 { color: #005a9e; border-bottom: 2px solid #005a9e; padding-bottom: 5px; }
        .report-header { background: #fff; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .dashboard { background: #e9ecef; padding: 15px; margin-bottom: 25px; border-radius: 8px; display: flex; gap: 15px; flex-wrap: wrap; }
        .dashboard span { padding: 8px 15px; border-radius: 5px; color: white; font-weight: bold; font-size: 1.1em; }
        .risk-critical { background-color: #dc3545; }
        .risk-high { background-color: #fd7e14; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #28a745; }
        .risk-info { background-color: #17a2b8; }
        .risk-warning { background-color: #fd7e14; }
        .risk-error { background-color: #6c757d; }
        details { background: #fff; padding: 0; margin-bottom: 15px; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden; }
        summary { font-weight: bold; cursor: pointer; font-size: 1.2em; padding: 15px; background: #f1f3f5; }
        summary:hover { background: #e9ecef; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border-top: 1px solid #dee2e6; padding: 12px 15px; text-align: left; vertical-align: top; }
        th { background-color: #f8f9fa; color: #495057; font-weight: 600; }
        pre { white-space: pre-wrap; word-wrap: break-word; background: #212529; color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Consolas', 'Courier New', monospace; }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🛡️ AD-Guardian Security Report</h1>
        <p><b>Domain:</b> $domain</p>
        <p><b>Generated:</b> $(Get-Date)</p>
    </div>
    <h2>Dashboard</h2>
    <div class="dashboard">$dashboard</div>
"@
    
    $htmlBody = ""
    # Group by the source module for a more organized report
    $groupedResults = $Results | Where-Object { $_.Status -ne 'Pass' } | Group-Object SourceModule | Sort-Object Name
    foreach ($group in $groupedResults) {
        $htmlBody += "<h2>$($group.Name)</h2>"
        # Sort findings within each module by risk level
        $sortedFindings = $group.Group | Sort-Object @{ Expression = { @('Critical', 'High', 'Medium', 'Low', 'Info', 'Warning', 'Error').IndexOf($_.RiskLevel) } }

        foreach ($item in $sortedFindings) {
            $detailsHtml = ConvertTo-SafeHtml(($item.Details | Format-List | Out-String).Trim())
            $htmlBody += "<details><summary><span class='risk-$($item.RiskLevel.ToLower())' style='padding:3px 8px; margin-right: 10px;'>$($item.RiskLevel)</span>$($item.Finding)</summary>"
            $htmlBody += "<table><tr><th>Status</th><th>Details</th><th>Remediation</th></tr>"
            $htmlBody += "<tr><td>$($item.Status)</td><td><pre>$detailsHtml</pre></td><td>$($item.RemediationDescription)</td></tr>"
            $htmlBody += "</table></details>"
        }
    }
    
    if (-not $htmlBody) {
        $htmlBody = "<h2>All Checks Passed</h2><p>No security issues were found based on the executed audit modules. Well done!</p>"
    }

    $html = $htmlHeader + $htmlBody + "</body></html>"
    Set-Content -Path $reportPath -Value $html -Encoding UTF8
    Write-Host "`n📄 HTML report generated: $reportPath" -ForegroundColor Green
}

#endregion

#region Main Execution Loop

function Start-ADGuardian {
    [CmdletBinding()]
    param()
    
    do {
        Show-Menu
        $choice = Read-Host "Select an option (1-4)"
        switch ($choice) {
            '1' { Start-FullAudit }
            '2' { Start-SpecificAudit }
            '3' { Start-AuditWithRemediation }
            '4' { Write-Host "Goodbye!" -ForegroundColor Green; return }
            default { Write-Warning "Invalid choice. Please select a valid option." }
        }
        if ($choice -ne '4') {
            Read-Host "`nPress Enter to return to the menu..."
        }
    } while ($choice -ne '4')
}

# --- Start the main function ---
Start-ADGuardian

#endregion