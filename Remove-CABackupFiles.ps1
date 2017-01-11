<#
    .SYNOPSIS
    Remove Certificate Authority backup files for the selected path.

    .DESCRIPTION
    Script to remove Certificate Authority backup files created by the script "Backup-CertificationAuthority.ps1".
    The script is intended to run as a Scheduled Task.

    .EXAMPLE
    Remove-CABackupFiles.ps1 -RemoveCABackupScriptFile C:\PKI\Backup

    Removes all files in the containing folder C:\PKI\Backup.
    
    .INPUTS
    IO.DirectoryInfo

    .NOTES
    Created on:     2017-01-11 12:13
    Created by:     Philip Haglund
    Organization:   Gonjer.com
    Filename:       Remove-CABackupFiles.ps1
    Version:        0.1
    Requirements:   Powershell 3.0
    Changelog:      2017-01-11 12:13 - Creation of script.

    .LINK
    https://www.gonjer.com
#>
[cmdletbinding()]
param (
    # Specify a fully qualified directory path for PKI backup location.
    # Example: C:\PKI\Backup
    [Parameter(
            Mandatory = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specify a fully qualified directory path for PKI backup location.`nExample: C:\PKI\Backup"
    )]
    [ValidateNotNullOrEmpty()]
    [IO.DirectoryInfo]$RemoveCABackupScriptFile
)
begin
{
    try
    {
        $items = Get-ChildItem -Path $RemoveCABackupScriptFile -ErrorAction Stop
    }
    catch
    {
        Write-Error -Message "Unable to get items for path $($RemoveCABackupScriptFile) - $($_.Exception.Message)"
        exit 2
    }
}
process
{
    foreach ($item in $items)
    {
        Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
    }
}
end
{
    try
    {
        $items = Get-ChildItem -Path $RemoveCABackupScriptFile -ErrorAction Stop
        if ($items.Length -ne 0)
        {
            Write-Error -Message "Backup files stille exist under path $($RemoveCABackupScriptFile)"
            exit 1
        }
    }
    catch
    {
        Write-Error -Message "Unable to get items for path $($RemoveCABackupScriptFile) - $($_.Exception.Message)"
        exit 2
    }
}