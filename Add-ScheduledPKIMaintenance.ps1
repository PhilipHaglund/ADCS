function Add-ScheduledPKIMaintenance
{
    <#
        .SYNOPSIS
        Creates a Scheduled Task that mail a PKI maintenance job every third month.
        
        .DESCRIPTION
        Creates and register a Scheduled Task containing a Powershell script action that will send a mail containing a recommended to do list for a three month PKI maintenance job.
        Default the task will be run every 91 days. 
        
        .EXAMPLE
        Add-ScheduledPKIMaintenance -CRTFile 'C:\Windows\system32\certsrv\CertEnroll\Contoso-Subordinate-CA.crt' -MaintenanceScriptFile 'C:\PKI\PKI-MaintenanceJob.ps1' -Customer Contoso -SMTPServer smtp.contoso.net -ToAddress recipient@contoso.com -FromAddress noreply@contoso.com
        
        Creates and register a Scheduled Task containing a Powershell script action that will send a mail containing a recommended to do list for a three month PKI maintenance job.
        The parameters ToAddress, FromAddress and SMTP server will be outputed in the Action script (Example: C:\PKI\PKI-MaintenanceJob.ps1).
        The parameter Customer is used to populate the HTML body text and Subject string in POwershell action script.

        .INPUTS
        String
        IO.FileInfo
        mailaddress
        
        .NOTES
        Created on:     2017-01-04 09:22
        Created by:     Philip Haglund
        Organization:   Gonjer.com
        Filename:       Add-ScheduledPKIMaintenance.ps1
        Version:        0.1
        Requirements:   Powershell 3.0
        Changelog:      2017-01-04 09:22 - Creation of script.
                        2017-01-11 07:39 - Change HTML body. Rewrite help. Fix typos.

        .LINK
        https://www.gonjer.com
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

<p><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Follow the to-do list below to keep the PKI structure/environment healthy and up to date.<br />
<em>The to-do list is just a recomendation, not a forced task list.</em></span></span><br />
&nbsp;</p>

<ul>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Remove unused &quot;Issued Certificate Templates&quot;.<br />
	<span id='result_box' lang='en'><span class='alt-edited'>Review the</span> the Issued Certificate Cemplates that are published.<br />
	Issued Certificate Templates that are not relevant or valid shall be removed from publication.</span><br />
	<br />
	<em><span id='result_box' lang='en'>How do you know if a certificate template is not valid? Check the following three items:<br />
	* Are the any Issued Certificates that use Certificate Template (see Issued Certificates).<br />
	* What AD objects or groups can request certificates, are these AD objects available in Active Directory or does the template contain broken SIDs (see Manage Certificate Templates).<br />
	* Is the name of the certificate template using the correct naming standard (standard refers to the internal company naming standard or company name followed by underscore, no spaces anywhere).</span></em></span></span><br />
	&nbsp;</li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Remove/Revoke stale/unsused &quot;Issued Certificates&quot;.<br />
	<span id='result_box' lang='en'><span class='alt-edited'>Review the</span> the certificates are issued and revoke expired certificates.<br />
	Sort the list on the &quot;Certificate Expiration Date&quot; (see Issued Certificates).<br />
	Select the certificates that has expired. Right-click on of the selected certificates, select &quot;All Tasks&quot;, then select &quot;Revoke Certificate&quot;.<br />
	<br />
	In the &quot;Reason Code&quot; option we choose &quot;Cease of Operation&quot;. The date and time that is the default is today&#39;s date, which is correct.</span></span></span><br />
	&nbsp;</li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Fix ACL Access rights for &quot;Certificate Templates&quot;.<br />
	<span id='result_box' lang='en'>There should be no &quot;single AD Objects&quot; as ACL access rights on a certificate template.<br />
	It&#39;s recomended to use an associated AD group to link together the enroll privileges. The reason for this is that it makes you manage who can enroll certificates more easily and you can utilize &quot;</span>Delegated <span lang='en'>Administration&quot; in Active Directory.</span></span></span><br />
	&nbsp;</li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Verifiy the max Validity Period on Certificate Templates.<br />
	<span id='result_box' lang='en'>The Certificate Templates validity period shall not exced the CA-certificate chain expiration date.<br />
	So if the root CA certificate expires 2024-02-22 and Subordinate CA certificate expires 2019-01-26 and the date today is 2017-01-11 the max validity period of issued certificates does no exced the CA-certificate chain expiration date.<br />
	If the date today is 2017-03-17 and Suborindate CA certificate expires 2019-01-26 the max validity period of two years exceeds the Subordinate CA-Certificate.<br />
	The recommended maximum length of certificate templates is 2 years. In exceptional cases, it may be possible to use three years.<br />
	If the validity period exceds the CA-certificate chain the recommended action is to make a plan/change request to renew the CA-certificate.</span></span></span><br />
	&nbsp;</li>
	<li><span style='font-size:11px;'><span style='font-family: verdana,geneva,sans-serif;'>Verify PKI Backup.<br />
	<span id='result_box' lang='en'>Verification of the backuped up <span>files need to</span> <span>be made</span><span>.</span> Make a restore test  <span>from the file backup</span><span>.</span><br />
	Good way to verify the files <span>is to go through</span> <span>the registry file</span><span> and</span> <span>CAPolicy.inf</span> <span>is to open and verify the content inte notepad. </span>CA certificate MMC and verify that it is intact.<br />
	If t<span>he system can</span> <span>read the files</span> <span>and the manual verify looks OK, the backup is intact.<br />
	There is no need to run a CA-restore.</span></span></span></span><br />
	<br />
	&nbsp;</li>
</ul>

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
            if (Test-Path -Path $MaintenanceScriptFile.Directory.FullName)
            {
                $null = New-Item -Path $MaintenanceScriptFile.Directory.FullName -ItemType Directory -Force -ErrorAction Stop
            }
            $maintenancescript | Out-File -FilePath $MaintenanceScriptFile -ErrorAction Stop -Force -Encoding ascii
        }
        catch
        {
            Write-Warning -Message "Unable to create file $($MaintenanceScriptFile) - $($_.Exception.Message)"
            Write-Output -InputObject 'Will not create a scheduled task. Contact your PKI Administrator!'
            break
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
            break
        }
    }
    process
    {
        try
        {
            $taskaction    = New-ScheduledTaskAction -Execute "$($PSHOME)\powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"& $MaintenanceScriptFile`"" -ErrorAction Stop
            $tasktrigger   = New-ScheduledTaskTrigger -DaysInterval 91 -At $crtdate -Daily -ErrorAction Stop
            $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest -ErrorAction Stop
            $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd -ErrorAction Stop
            $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every 3 months.' -ErrorAction Stop

            Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Customer) - PKI 3 Month Maintenance" -Force -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Unable to create a ScheduledTask containing '$($Customer) - PKI 3 Month Maintenance' - $($_.Exception.Message)"
            Write-Output -InputObject 'Contact your PKI Administrator!'
            break
        }
    }    
}