<#+
.SYNOPSIS
    Finds user and computer accounts inactive for more than the threshold in config.json.
.DESCRIPTION
    Audits for stale user and computer accounts. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-StaleAccounts {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    $threshold = (Get-Date).AddDays(-[int]$Config.staleAccountThresholdDays)
    foreach ($type in @('User','Computer')) {
        try {
            $accounts = Get-ADObject -Filter { (ObjectClass -eq $type) -and (lastLogonTimeStamp -lt $threshold) } -Properties lastLogonTimeStamp,SamAccountName
            foreach ($acct in $accounts) {
                $finding = "$type account $($acct.SamAccountName) is stale (last logon: $([datetime]::FromFileTime($acct.lastLogonTimeStamp)))"
                $results += [PSCustomObject]@{
                    Status    = "Fail"
                    Finding   = $finding
                    RiskLevel = "Medium"
                    Details   = $acct | Select-Object SamAccountName, lastLogonTimeStamp
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Status    = "Error"
                Finding   = "Could not enumerate $type accounts"
                RiskLevel = "Medium"
                Details   = $_.Exception.Message
            }
        }
    }
    return $results
} 