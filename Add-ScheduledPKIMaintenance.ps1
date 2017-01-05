function Add-ScheduledPKIMaintenance
{
    <#
        .SYNOPSIS
        Function used for something that is created.
        
        .DESCRIPTION
        Function used for something that is created and this needs more descritive informaiton.
        
        .EXAMPLE
        Add-ScheduledPKIMaintenance -CRTFile ParameterInput 'C:\Windows\system32\certsrv\CertEnroll\Contoso-Subordinate-CA.crt' -MaintenanceScriptFile 'C:\PKI\PKI-MaintenanceJob.ps1' -Customer Contoso -SMTPServer smtp.contoso.net -ToAddress recipient@contoso.com -FromAddress noreply@contoso.com
        
        Creates and register a Scheduled Task containing a Powershell script that will send a mail containing a recommended to do list for a three month PKI maintenance job.

        .INPUTS
        String
        IO.FileInfo
        mailaddress
        
        .NOTES
        Created on:     2017-01-04 09:22
        Created by:     Philip Haglund
        Organization:   Gonjer.com
        Filename:       Add-ScheduledPKIMaintenance
        Version:        1.0
        Requirements:   Powershell *.*
        Changelog:      2017-01-04 09:22 - Creation of script.

        .LINK
        http://www.gonjer.com
    #>
    [cmdletbinding()]
    param (
        # Specify a fully qualified file path for the .CRT File.
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'C:\Windows\system32\certsrv\CertEnroll\Contoso-Subordinate-CA.crt'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.crt$')]
        [ValidateScript({
                    if (Test-Path -Path $_)
                    {
                        $True
                    }
                    else
                    {
                        throw "The path '$_' is not available."
                    }
        })]
        [Alias('CRT')]
        [IO.FileInfo]$CRTFile,

        # Specify a fully qualified file path for the script file that contains the mail information for PKI Maintenance.
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'C:\PKI\PKI-MaintenanceJob.ps1'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.ps1$')]
        [IO.FileInfo]$MaintenanceScriptFile,

        # A Customer Name used to populate the email template with correct information.
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'Contoso'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Customer,

        # A valid SMTP Server used to send information messages about PKI maintenance.
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'Enter a valid SMTPServer. Example: smtp.contoso.net'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$SMTPServer,

        # One or more valid TO mailaddresses used to send information messages about PKI maintenance.
        # Example: noreply@contoso.com
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'One or more valid TO mailaddresses. Example: recipient@contoso.com'
        )]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]$ToAddress,

        # A valid FROM mailaddress used to send information messages about PKI maintenance.
        # Example: noreply@contoso.com
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'Enter a valid mailaddress. Example: noreply@contoso.com'
        )]
        [ValidateNotNullOrEmpty()]
        [mailaddress]$FromAddress

    )
    begin
    {
        $body = @"
"<h1><span style='font-size:14px;'><span style='font-family: verdana,geneva,sans-serif;'>It&#39;s time for PKI maintenance!</span></span></h1>

<p><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>It was three months ago since the last PKI maintenance for $($Customer).</span></span></p>

<p><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Follow the Knowledgebase <a href='https://servicedesk.zetup.se/kb_view.do?sysparm_article=KB0011071#Rutin' target='_blank'>KB0011071</a> (https://servicedesk.zetup.se/kb_view.do?sysparm_article=KB0011071#Rutin).</span></span></p>

<p><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>The KB contains a to do list for:</span></span></p>

<ul>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Remove unused &quot;Issued Certificate Templates&quot;.</span></span></li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Remove/Revoke stale/unsused &quot;Issued Certificates&quot;.</span></span></li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Fix ACL Access rights for &quot;Certificate Templates&quot;. Shall not contains single AD-Objects.</span></span></li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Verifiy the max Validity Period on Certificate Templates.</span></span></li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Verify PKI Backup.</span></span></li>
</ul>

<p>&nbsp;</p>

<p><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Regards<br />
Your PKI Administrator</span></span></p>"
"@


        $maintenancescript = @"
Send-MailMessage ``
-To '$($ToAddress)' ``
-BodyAsHtml ``
-Encoding ([System.Text.Encoding]::UTF8) ``
-From '$($FromAddress)' ``
-SmtpServer '$($SMTPServer)' ``
-Subject 'PKI maintenance - $($Customer)' ``
-Body $($body)
"@
        try
        {
            $maintenancescript | Out-File -FilePath $MaintenanceScriptFile -ErrorAction Stop -Force -Encoding ascii
        }
        catch
        {
            Write-Warning -Message "Unable to create file $($MaintenanceScriptFile) - $($_.Exception.Message)"
            Write-Output -InputObject 'Will not create a scheduled task. Contact your PKI Administrator!'
            return
        }
        
        try
        {
            [string]$regex = '^(?:[a-z]+\:\s)(?<Date>\d{4}\-\d{2}-\d{2})(?:\s)(?<Time>\d{2}\:\d{2})(?:.*)$'
            $crtdump = & "$env:windir\system32\certutil.exe" -dump $($CRTFile)
            $null = ($crtdump -match 'NotBefore').Trim() -match $regex
            [datetime]$crtdate = $Matches['Date']
        }
        catch
        {
            Write-Warning -Message "Unable to determine the datetime object for $CRTFile - $($_.Exception.Message)"
            Write-Output -InputObject 'Will not create a scheduled task. Contact your PKI Administrator!'
            return
        }
    }
    process
    {
        try
        {
            $taskaction    = New-ScheduledTaskAction -Execute "$($PSHOME)\powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"& $MaintenanceScriptFile`""
            $tasktrigger   = New-ScheduledTaskTrigger -DaysInterval 91 -At $crtdate -Daily
            $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest
            $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd
            $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every 3 months.'

            Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Customer) - PKI 3 Month Maintenance" -Force
        }
        catch
        {
            Write-Warning -Message "Unable to create a ScheduledTask containing '$($Customer) - PKI 3 Month Maintenance' - $($_.Exception.Message)"
            Write-Output -InputObject 'Contact your PKI Administrator!'
            return
        }
    }    
}