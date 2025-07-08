<#+
.SYNOPSIS
    Enables Kerberos preauthentication for a user account.
.DESCRIPTION
    Prompts for confirmation and enables preauthentication for the specified user.
.PARAMETER SamAccountName
    The SamAccountName of the user to update.
#>
function Fix-ASREPBroastable {
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )
    Write-Host "You are about to enable Kerberos preauthentication for user: $SamAccountName" -ForegroundColor Yellow
    $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Action cancelled by user." -ForegroundColor Cyan
        return
    }
    try {
        Set-ADUser -Identity $SamAccountName -DoesNotRequirePreAuth $false -ErrorAction Stop
        Write-Host "Kerberos preauthentication has been enabled for $SamAccountName." -ForegroundColor Green
    } catch {
        Write-Host "Failed to update $SamAccountName: $_" -ForegroundColor Red
    }
} 