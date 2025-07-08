<#+
.SYNOPSIS
    Removes a user from a privileged group.
.DESCRIPTION
    Prompts for confirmation and removes the specified user from the specified group.
.PARAMETER SamAccountName
    The SamAccountName of the user to remove.
.PARAMETER GroupName
    The name of the privileged group.
#>
function Remove-UserFromPrivilegedGroup {
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,
        [Parameter(Mandatory)]
        [string]$GroupName
    )
    Write-Host "You are about to remove user $SamAccountName from group $GroupName" -ForegroundColor Yellow
    $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Action cancelled by user." -ForegroundColor Cyan
        return
    }
    try {
        Remove-ADGroupMember -Identity $GroupName -Members $SamAccountName -Confirm:$false -ErrorAction Stop
        Write-Host "User $SamAccountName has been removed from $GroupName." -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove user $SamAccountName from $GroupName: $_" -ForegroundColor Red
    }
} 