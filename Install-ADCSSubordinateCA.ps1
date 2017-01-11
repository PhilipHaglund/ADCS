#requires -Modules NetTCPIP, ServerManager
<#
        .SYNOPSIS
        Installs the Subordinate Certificate Authority role and configures it.
    
        .DESCRIPTION
        Script developed for to install a Subordinate Certificate Authority when a Root (Offline) Certificate Authority is already installed and configured.
        The configuration uses certutil.exe to modify the CA settings.
        Tested on Windows Server 2012R2 and Server 2016.

        .EXAMPLE
        Install-ADCSSubordinateCA.ps1 -Customer Demo -DomainURL pki.demo.com

        This will install the install and configure the Certificate Authority Service with the CA name "Demo-Subordinate-CA".
        It will create the PKI folder in the default location ("$env:SystemDrive\PKI").
        The PKI folder contains the Database and paths for AIA and CRL.
        A Web Virtual Directory will be created with the name PKI mapped to "$env:SystemDrive\PKI\Web"
        Three scheduled tasks will be created 


        .EXAMPLE
        Install-ADCSSubordinateCA.ps1 -Customer Contoso -DomainURL pki.contoso.com -LocalPKIPath E:\CALocation

        This will install the install and configure the Certificate Authority Service with the CA name "Contoso-Subordinate-CA".
        It will create a folder named CALocation in E:\.
        The PKI folder contains the Database and paths for AIA and CRL.
        A Web Virtual Directory will be created with the name PKI mapped to "E:\CALocation\Web"
            
        .NOTES
        Created on:     2016-05-11 09:15
        Created by:     Philip Haglund
        Organization:   Gonjer.com for Zetup AB
        Filename:       Install-ADCSSubordinateCA.ps1
        Version:        0.5
        Requirements:   Powershell 4.0 (Module: NetTCPIP, ServerManager)
        Changelog:      2016-05-11 09:15 - Creation of script
                        2016-09-19 16:25 - Removed LDAP paths CRL: "\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10" AIA: \n3:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11
                        2016-09-20 09:10 - Removed SMB Share requirements.
                        2016-10-07 15:21 - Completly changed the prompt text for the manual steps. Minor bugfixes and corrections based on PSSharper.
                        2017-01-10 14:03 - Set web.config to hidden. Added Group Policy recommendation for auto enrollment.
                        2017-01-11 14:57 - Added functions 'Register-CABackup' and 'Add-ScheduledPKIMaintenance'. Change ValidityPeriod to 30 months instead of 2 years.
        .LINK
        https://www.gonjer.com
        http://www.zetup.se
#>
#requires -Version 4.0
[cmdletbinding(
    SupportsShouldProcess = $true
)]
param (

    # Customer name that will belong in the Certificate Authority Name.
    # Example: 'DEMO' will be "DEMO-Subordinate-CA"
    [Parameter(
            Mandatory = $true,
            HelpMessage = "Customer name that will belong in the Certificate Authority Name.`nExample: 'DEMO'`n'DEMO' will be 'DEMO-Subordinate-CA'"
    )]
    [string]$Customer,

    # Domain URL for CRL and AIA publishing. Also used for the fileshare path.
    # Example: 'pki.demo.com'
    [Parameter(
            Mandatory = $true,
            HelpMessage = "Domain URL for CRL and AIA publishing.`nExample: 'pki.demo.com'"
    )]
    [string]$DomainURL,

    # Local file path to store Certificate Database and Logs. Also used for creating Web directory and fileshare location.
    # Example: 'C:\PKI'    
    [Alias('Path')]
    [string]$LocalPKIPath = "$env:SystemDrive\PKI",

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
    #region Create a prompt function to allow for manual steps in the script.
    function Confirm-ToContinue
    {
        $caption = 'Manual Step'  
        $message = 'Are you done with the manual step?'
        [int]$defaultChoice = 1
        $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Done with manual step.'
        $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Not done, continue to prompt.'
        $cancel = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Cancel', 'Not done, exit script.'
        $options = [Management.Automation.Host.ChoiceDescription[]]($yes, $no, $cancel)
        
        $do = $true
        do
        {            
            $choice = $Host.ui.PromptForChoice($caption,$message, $options,$defaultChoice)
            switch ($choice)
            {
                0 
                {
                    $do = $false
                }
                1 
                {
                    'Not done, continue to prompt.'
                    $do = $true
                }
                Default 
                {
                    'Cancel, exiting script.'
                    $do = $false
                    break
                }
            }
        }
        while ($do)
    }
    #endregion Create a prompt function to allow for manual steps in the script.

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

    function Register-CABackup
    {
        <#
            .SYNOPSIS
            Creates two Scheduled Tasks. One for backup of PKI environment and one for removal of the backup files.
        
            .DESCRIPTION
            Creates and register two Scheduled Tasks each containing a Powershell script action. One script will backup the PKI environment and one will remove those backup files created.
            The Scheduled Tasks is configured to run once a week.
    
            All credits for the Backup-CertificationAuthority.ps1 script goes to @Crypt32 (Vadims Podāns), the script is untouched, only used in the backupscript-scriptblock.        
        
            .EXAMPLE
            Register-CABackup -CABackupScriptFile 'C:\PKI\Backup-CertificationAuthority.ps1' -RemoveCABackupScriptFile 'C:\PKI\Remove-CABackupFiles.ps1' -Customer Contoso
    
            Creates and register two Scheduled Tasks each containing a Powershell script action 'C:\PKI\Backup-CertificationAuthority.ps1' / 'C:\PKI\Remove-CABackupFiles.ps1'.
            
            .INPUTS
            IO.FileInfo
            string
        
            .NOTES
            Created on:     2017-01-11 12:13
            Created by:     Philip Haglund
            Organization:   Gonjer.com
            Filename:       Register-CABackup
            Version:        0.1
            Requirements:   Powershell 3.0
            Changelog:      2017-01-11 12:13 - Creation of script.
                            
    
            .LINK
            https://www.gonjer.com
        #>
        [cmdletbinding()]
        param (
            # Specify a fully qualified file path for the script file that contains PKI Backup script.
            [Parameter(
                    Mandatory = $True,
                    ValueFromPipelineByPropertyName = $True,
                    HelpMessage = 'C:\PKI\Backup-CertificationAuthority.ps1'
            )]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern('^.*\.ps1$')]
            [IO.FileInfo]$CABackupScriptFile,
    
            # Specify a fully qualified file path for the script file that contains PKI Remove Backup files.
            [Parameter(
                    Mandatory = $True,
                    ValueFromPipelineByPropertyName = $True,
                    HelpMessage = 'C:\PKI\Remove-CABackupFiles.ps1'
            )]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern('^.*\.ps1$')]
            [IO.FileInfo]$RemoveCABackupScriptFile,
    
            # Customer name that belongs to the Certificate Authority Name.
            [Parameter(
                    Mandatory = $true,
                    HelpMessage = 'Customer name that will belong in the Certificate Authority Name.'
            )]
            [string]$Customer
        )
        begin
        {
            $date = Get-Date
    
            #region Backupscript-scriptblock
            $backupscript = {            
            [CmdletBinding()]
    	        param(
    		        [Parameter(Mandatory = $true)]
    		        [IO.DirectoryInfo]$Path,
    		        [ValidateSet("Full","Incremental")]
    		        [string]$Type = "Full",
    		        [string]$Password,
    		        [switch]$BackupKey,
    		        [switch]$KeepLog,
    		        [switch]$Extended,
    		        [switch]$Force
    	        )
    
    	        if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
    	        if ($PSBoundParameters.Debug) {
    		        $Host.PrivateData.DebugForegroundColor = "Cyan"
    		        $DebugPreference = "continue"
    	        }
            #region Defining low-level APIs
    
$cadmsignature = @"
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CertSrvIsServerOnline(
	string pwszServerName,
	ref bool pfServerOnline
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupPrepare(
	string pwszServerName,
	uint grbitJet,
	uint dwBackupFlags,
	ref IntPtr phbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetDatabaseNames(
	IntPtr hbc,
	ref IntPtr ppwszzAttachmentInformation,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetBackupLogs(
	IntPtr hbc,
	ref IntPtr ppwszzBackupLogFiles,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetDynamicFileList(
	IntPtr hbc,
	ref IntPtr ppwszzFileList,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupOpenFile(
	IntPtr hbc,
	string pwszAttachmentName,
	int cbReadHintSize,
	ref Int64 pliFileSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupRead(
	IntPtr hbc,
	IntPtr pvBuffer,
	int cbBuffer,
	ref int pcbRead
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupClose(
	IntPtr hbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupTruncateLogs(
	IntPtr hbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupEnd(
	IntPtr phbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupFree(
	IntPtr pv
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvRestoreGetDatabaseLocations(
	IntPtr hbc,
	ref IntPtr ppwszzDatabaseLocationList,
	ref uint pcbSize
);
"@
            #endregion
    
            #region add defined types
    	        try {Add-Type -MemberDefinition $cadmsignature -Namespace PKI -Name CertAdm}
    	        catch {break}
            #endregion
    
            #region Path checking
    	        if (Test-Path $Path) {
    		        if (Test-Path $Path\DataBase) {
    			        if ($Force) {
    				        try {
    					        Remove-Item $Path\DataBase -Recurse -Force -ErrorAction Stop
    					        $BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop
    				        } catch {
    					        Write-Error -Category InvalidOperation -ErrorId "InvalidOperationDeleteException" `
    					        -ErrorAction Stop -Message $Error[0].Exception
    				        }
    			        } else {
    				        Write-Error -Category ResourceExists -ErrorId "ResourceExistsException" `
    				        -ErrorAction Stop -Message "The path '$Path\DataBase' already exist."
    			        }
    		        } else {
    			        $BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop
    		        }
    	        } else {
    		        try {$BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop}
    		        catch {
    			        Write-Error -Category ObjectNotFound -ErrorId "PathNotFoundException" `
    			        -ErrorAction Stop -Message "Cannot create object in '$Path'"
    		        }
    	        }
            #endregion
    
            #region helper functions
    	        function Split-BackupPath ([Byte[]]$Bytes) {
    		        $SB = New-Object System.Text.StringBuilder
    		        $bytes1 = $bytes | ForEach-Object {"{0:X2}" -f $_}
    		        for ($n = 0; $n -lt $bytes1.count; $n = $n + 2) {
    			        [void]$SB.Append([char](Invoke-Expression 0x$(($bytes1[$n+1]) + ($bytes1[$n]))))
    		        }
    		        $SB.ToString().Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
    	        }
    	        function __BackupKey ($Password) {
    		        $CertConfig = New-Object -ComObject CertificateAuthority.Config
    		        try {$local = $CertConfig.GetConfig(3)}
    		        catch { }
    		        if ($local -ne $null) {
    			        $name = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration' -Name Active).Active
    			        $StoreCerts = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    			        $Certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    			        $TempCerts = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    			        $Store = New-Object Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
    			        $Store.Open("ReadOnly")
    			        $StoreCerts = $Store.Certificates
    			        $Store.Close()
    			        $Certs = $StoreCerts.Find("FindBySubjectName",$name,$true)
    			        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    			        $chain.ChainPolicy.RevocationMode = "NoCheck"
    			        $Certs | ForEach-Object {
    				        [void]$chain.Build($_)
    				        if ($chain.ChainElements.Count -ge 1) {
    					        for ($n = 1; $n -lt $chain.ChainElements.Count; $n++) {
    						        [void]$TempCerts.Add($chain.ChainElements[$n].Certificate)
    					        }
    				        }
    				        $chain.Reset()
    			        }
    			        if ($TempCerts.Count -gt 0) {
    				        $Certs.AddRange([Security.Cryptography.X509Certificates.X509Certificate2[]]($TempCerts | Select-Object -Unique))
    			        }
    			        try {[IO.File]::WriteAllBytes("$Path\$Name.p12",$Certs.Export("pfx",$Password))}
    			        finally {$StoreCerts, $Certs, $TempCerts | ForEach-Object {$_.Clear()}}
    		        }
    	        }
    	        # helper function for backup routine
    	        function __BackupRoutine ($phbc,$File,$BackupDir,$pvBuffer, $cbBuffer, $FileType) {
    		        $n = 1
    		        Write-Debug "Read buffer address: $pvBuffer"
    		        $FileName = Get-Item $File -ErrorAction SilentlyContinue
    		        $pliFileSize = 0
    		        Write-Debug "Open current item: $file"
    		        # open DB file. I set 0 for cbReadHintSize to allow system to automatically select proper buffer size
    		        $hresult = [PKI.CertAdm]::CertSrvBackupOpenFile($phbc,$File,$cbBuffer,[ref]$pliFileSize)
    		        if ($hresult -ne 0) {
    			        $StatusObject.Status = 0x8007004
    			        __status $StatusObject
    			        break
    		        }
    		        Write-Debug "Current item size in bytes: $pliFileSize"
    		        $BackupFile = New-Item -Name $FileName.Name -ItemType file -Path $BackupDir -Force -ErrorAction Stop
    		        $FS = New-Object IO.FileStream $BackupFile,"append","write"
    		        [int]$pcbRead = 0
    		        $complete = 0
    		        $Name = (Get-Item $File -Force -ErrorAction SilentlyContinue).Name
    		        while (!$last) {
    			        $n++
    			        [int]$percent = $complete / $pliFileSize * 100
    			        Write-Progress -Activity "Backing up database file '$name' " -CurrentOperation InnerLoop -PercentComplete $percent `
    			        -Status "$percent% complete"
    			        $hresult = [PKI.CertAdm]::CertSrvBackupRead($phbc,$pvBuffer,$cbBuffer,[ref]$pcbRead)
    			        if ($hresult -ne 0) {
    				        $StatusObject.Status = 0x800701e
    				        __status $StatusObject
    				        break
    			        }
    			        if ($FileType -eq "database") {$script:Size += $pcbRead}
    			        Write-Debug "Reading $n portion of $pcbRead bytes"
    			        $uBuffer = New-Object byte[] -ArgumentList $pcbRead
    			        [Runtime.InteropServices.Marshal]::Copy($pvBuffer,$uBuffer,0,$pcbRead)
    			        $FS.Write($uBuffer,0,$uBuffer.Length)
    			        $complete += $pcbRead
    			        if ($pcbRead -lt $cbBuffer) {$last = $true}
    		        }
    		        Write-Debug "Closing current item: $file"
    		        $FS.Close()
    		        $hresult = [PKI.CertAdm]::CertSrvBackupClose($phbc)
    		        Write-Debug "Current item '$BackupFile' is closed: $(!$hresult)"
    		        # relelase managed and unmanaged buffers
    		        Remove-Variable uBuffer
    	        }
    	        function __status ($StatusObject) {
    		        try {$StatusObject.StatusMessage = [PKI.Utils.Error]::GetMessage($StatusObject.Status)}
    		        catch { }
    		        Write-Verbose "Clearing resources"
    		        $hresult = [PKI.CertAdm]::CertSrvBackupEnd($phbc)
    		        Write-Debug "Backup sent to end state: $(!$hresult)"
    		        $StatusObject.BackupEnd = [datetime]::Now
    		        $StatusObject
    	        }
            #endregion
    
    	        $StatusObject = New-Object psobject -Property @{
    		        BackupType = $Type;
    		        Status = 0;
    		        StatusMessage = [string]::Empty;
    		        DataBaseSize = 0;
    		        LogFileCount = 0;
    		        BackupStart = [datetime]::Now;
    		        BackupEnd = [datetime]::Now
    	        }
    	        if ($BackupKey) {
    		        if ($Password -eq $null -or $Password -eq [string]::Empty) {
    			        $Password = Read-Host "Enter password"
    		        }
    		        __BackupKey $Password
    	        }
    	        $ofs = ", "
    	        Write-Verbose "Set server name to $($Env:computername)"
    	        $Server = $Env:COMPUTERNAME
    	        $ServerStatus = $false
    
    	        Write-Verbose "Test connection to local CA"
    	        $hresult = [PKI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus)
    	        if (!$ServerStatus) {
    		        $StatusObject.Status = 0x800706ba
    		        __status $StatusObject
    		        break
    	        }
    
    	        Write-Debug "Instantiate backup context handle"
    	        [IntPtr]$phbc = [IntPtr]::Zero
    
    	        Write-Debug "Retrieve backup context handle for the backup type: $type"
    	        $hresult = switch ($Type) {
    		        "Full" {[PKI.CertAdm]::CertSrvBackupPrepare($Server,0,1,[ref]$phbc)}
    		        "Incremental" {[PKI.CertAdm]::CertSrvBackupPrepare($Server,0,2,[ref]$phbc)}
    	        }
    	        if ($hresult -ne 0) {
    		        $StatusObject.Status = $hresult
    		        __status $StatusObject
    		        break
    	        }
    	        Write-Debug "Backup context handle is: $phbc"
    	
    	        $cbBuffer = 524288
    	        $pvBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($cbBuffer)
    	
    	        if ($Type -eq "Full") {
    		        Write-Debug "Retrieve restore map"
    		        $ppwszzDatabaseLocationList = [IntPtr]::Zero
    		        $pcbSize = 0
    		        $hresult = [PKI.CertAdm]::CertSrvRestoreGetDatabaseLocations($phbc,[ref]$ppwszzDatabaseLocationList,[ref]$pcbSize)
    		        Write-Debug "Restore map handle: $ppwszzDatabaseLocationList"
    		        Write-Debug "Restore map size in bytes: $pcbSize"
    		        $Bytes = New-Object byte[] -ArgumentList $pcbSize
    		        [Runtime.InteropServices.Marshal]::Copy($ppwszzDatabaseLocationList,$Bytes,0,$pcbSize)
    		        Write-Verbose "Writing restore map to: $BackupDir\certbkxp.dat"
    		        [IO.File]::WriteAllBytes("$BackupDir\certbkxp.dat",$Bytes)
    		        Remove-Variable Bytes -Force
    
    		        Write-Verbose "Retrieve DB file locations"
    		        $ppwszzAttachmentInformation = [IntPtr]::Zero
    		        $pcbSize = 0
    		        $hresult = [PKI.CertAdm]::CertSrvBackupGetDatabaseNames($phbc,[ref]$ppwszzAttachmentInformation,[ref]$pcbSize)
    		        Write-Debug "DB file location handle: $ppwszzAttachmentInformation"
    		        Write-Debug "DB file location size in bytes: $pcbSize"
    		        if ($hresult -ne 0) {
    			        $StatusObject.Status = $hresult
    			        __status $StatusObject
    			        break
    		        }
    		        if ($pcbSize -eq 0) {
    			        $StatusObject.Status = 0x80070012
    			        __status $StatusObject
    			        break
    		        }
    		        $Bytes = New-Object byte[] -ArgumentList $pcbSize
    		        [Runtime.InteropServices.Marshal]::Copy($ppwszzAttachmentInformation,$Bytes,0,$pcbSize)
    		        $DBPaths = Split-BackupPath $Bytes
    		        Write-Verbose "Unstripped DB paths:"
    		        $DBPaths | ForEach-Object {Write-Verbose $_}
    		        Remove-Variable Bytes
    		        # backup DB files
    		        # initialize read buffer
    		        Write-Debug "Set read buffer to: $cbBuffer bytes"
    		        $script:Size = 0
    		        foreach ($File in $DBPaths) {
    			        $File = $File.Substring(1,($File.Length - 1))
    			        Write-Verbose "Backing up file: $File"
    			        __BackupRoutine $phbc $File $BackupDir $pvBuffer $cbBuffer "database"
    		        }
    		        $StatusObject.DataBaseSize = $script:Size
    		        Remove-Variable DBPaths
    	        } else {
    		        Write-Verbose "Skipping CA database backup."
    		        Write-Debug "Skipping CA database backup. Logs only"
    	        }
    	        # retrieve log files
    	        $ppwszzBackupLogFiles = [IntPtr]::Zero
    	        $pcbSize = 0
    	        Write-Verbose "Retrieving DB log file list"
    	        $hresult = [PKI.CertAdm]::CertSrvBackupGetBackupLogs($phbc,[ref]$ppwszzBackupLogFiles,[ref]$pcbSize)
    	        Write-Debug "Log file location handle: $ppwszzAttachmentInformation"
    	        Write-Debug "Log file location size in bytes: $pcbSize"
    	        if ($hresult -ne 0) {
    		        $StatusObject.Status = 0x80070012
    		        __status $StatusObject
    		        break
    	        }
    	        $Bytes = New-Object byte[] -ArgumentList $pcbSize
    	        [Runtime.InteropServices.Marshal]::Copy($ppwszzBackupLogFiles,$Bytes,0,$pcbSize)
    	        $LogPaths = Split-BackupPath $Bytes
    	        $StatusObject.LogFileCount = $LogPaths.Length
    	        Write-Verbose "Unstripped LOG paths:"
    	        $LogPaths | ForEach-Object {Write-Verbose $_}
    	        Remove-Variable Bytes
    	        foreach ($File in $LogPaths) {
    		        $File = $File.Substring(1,($File.Length - 1))
    		        Write-Verbose "Backing up file: $File"
    		        __BackupRoutine $phbc $File $BackupDir $pvBuffer $cbBuffer "log"
    	        }
    	        [Runtime.InteropServices.Marshal]::FreeHGlobal($pvBuffer)
    	        Remove-Variable LogPaths
    	        Write-Debug "Releasing read buffer"
    	        # truncate logs
    	        if ($Type -eq "Full" -and !$KeepLog) {
    		        Write-Verbose "Truncating logs"
    		        Write-Debug "Truncating logs"
    		        $hresult = [PKI.CertAdm]::CertSrvBackupTruncateLogs($phbc)
    		        if ($hresult -ne 0) {
    			        $StatusObject.Status = 0x80070012
    			        __status $StatusObject
    			        break
    		        }
    	        }
    	        # retrieve and backup dynamic files
    	        if ($Extended) {
    		        $Now = Get-Date -Format dd.MM.yyyy
    		        Write-Verbose "Export CA configuration registry hive and CAPolicy.inf (if possible)."
    		        Write-Debug "Export CA configuration registry hive and CAPolicy.inf (if possible)."
    		        reg export "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" "$Path\CAConfig-$($Now.ToString()).reg" /y | Out-Null
    		        Copy-Item $Env:windir\CAPolicy.inf -Destination $Path -Force -ErrorAction SilentlyContinue
    	        }
    	        __status $StatusObject
    
            }
            #endregion Backupscript-scriptblock
            #region Removebackupfiles-scriptblock
            $removebackupfiles = {
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
                    http://www.gonjer.com
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
            }
            #endregion Removebackupfiles-scriptblock
        }
        process
        {
            #region Create CABackupScriptFile Scheduled Task
            try
            {
                if (Test-Path -Path $CABackupScriptFile.Directory.FullName)
                {
                    $null = New-Item -Path $CABackupScriptFile.Directory.FullName -ItemType Directory -Force -ErrorAction Stop
                }
                $backupscript.ToString() | Out-File -FilePath $CABackupScriptFile -ErrorAction Stop -Force -Encoding ascii -Width 4096
            }
            catch
            {
                Write-Warning -Message "Unable to create file $($CABackupScriptFile) - $($_.Exception.Message)"
                Write-Output -InputObject 'Will not create a scheduled task containing a Backup Certification Authority script. Contact your PKI Administrator!'
                return
            }
    
            try
            {
                $taskaction    = New-ScheduledTaskAction -Execute "$($PSHOME)\powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"& $CABackupScriptFile`"" -ErrorAction Stop
                $tasktrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At (Get-Date 18:00) -WeeksInterval 1 -ErrorAction Stop
                $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest -ErrorAction Stop
                $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd -ErrorAction Stop
                $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every friday at 18:00.' -ErrorAction Stop
    
                Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Customer) - Backup PKI" -Force -ErrorAction Stop
            }
            catch
            {
                Write-Warning -Message "Unable to create a ScheduledTask containing '$($Customer) - Backup PKI' - $($_.Exception.Message)"
                Write-Output -InputObject 'Contact your PKI Administrator!'
                return
            }
            #endregion Create CABackupScriptFile Scheduled Task
            #region Create RemoveCABackupScriptFile Scheduled Task
            try
            {
                if (Test-Path -Path $RemoveCABackupScriptFile.Directory.FullName)
                {
                    $null = New-Item -Path $RemoveCABackupScriptFile.Directory.FullName -ItemType Directory -Force -ErrorAction Stop
                }
                $removebackupfiles.ToString() | Out-File -FilePath $RemoveCABackupScriptFile -ErrorAction Stop -Force -Encoding ascii -Width 4096
            }
            catch
            {
                Write-Warning -Message "Unable to create file $($RemoveCABackupScriptFile) - $($_.Exception.Message)"
                Write-Output -InputObject 'Will not create a scheduled task containing a Backup Certification Authority script. Contact your PKI Administrator!'
                return
            }
            try
            {
                $taskaction    = New-ScheduledTaskAction -Execute "$($PSHOME)\powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -Command `"& $RemoveCABackupScriptFile`"" -ErrorAction Stop
                $tasktrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At (Get-Date 22:00) -WeeksInterval 1 -ErrorAction Stop
                $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest -ErrorAction Stop
                $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd -ErrorAction Stop
                $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every sunday at 22:00.' -ErrorAction Stop
    
                Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Customer) - Remove PKI Backup files" -Force -ErrorAction Stop
            }
            catch
            {
                Write-Warning -Message "Unable to create a ScheduledTask containing '$($Customer) - Remove PKI Backup files' - $($_.Exception.Message)"
                Write-Output -InputObject 'Contact your PKI Administrator!'
                return
            }
            #endregion Create RemoveCABackupScriptFile Scheduled Task        
        }
    }
    
    # Clear all errors    
    $Error.Clear()
}
process
{
    if ($PSCmdlet.ShouldProcess("$($Customer)($($DomainURL)) - $($LocalPKIPath)",'Configure Subordinate CA'))
    {
        #region Get Local IP-address
        try
        {
            $ipaddress = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object -FilterScript {
                    $_.DefaultIpGateway
            })[0].IPAddress[0]
        }
        catch
        {
            $ipaddress = (Get-NetIPAddress | Where-Object -FilterScript {
                    $_.InterfaceAlias -notlike '*Loopback*' -and $_.InterfaceAlias -notlike 'vEthernet*' -and $_.IPAddress -notlike '169.254*' -and $_.AddressFamily -like 'IPv4'
            }).IPAddress
        }
        #endregion Get Local IP-address
        
        #region Install Windowsfeature ADCS-Cert-Authority, Adcs-Web-Enrollment
        try
        {
            $null = Install-WindowsFeature -Name ADCS-Cert-Authority, Adcs-Web-Enrollment -IncludeManagementTools -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message 'Unable to install Windows Feature ADCS-Cert-Authority'
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject 'Exiting script'
            return
        }
        #endregion Install Windowsfeature ADCS-Cert-Authority, Adcs-Web-Enrollment
        
        #region Create directories
        $certdb  = New-Item -Path "$($LocalPKIPath)\Database\CertDB" -ItemType Directory -Force
        $certlog = New-Item -Path "$($LocalPKIPath)\Database\CertLog" -ItemType Directory -Force
        $webpath = New-Item -Path "$($LocalPKIPath)\Web" -ItemType Directory -Force
        $crlpath = New-Item -Path "$($LocalPKIPath)\Web\CRL" -ItemType Directory -Force
        $aiapath = New-Item -Path "$($LocalPKIPath)\Web\AIA" -ItemType Directory -Force

        #endregion Create directories
          
        #region Generate a CAPolicy.inf file for "$($env:windir)\CAPolicy.inf"
        $confignc = ([ADSI]'LDAP://RootDse').configurationNamingContext
        
        $capolicy = '[Version]
Signature="$Windows NT$"

[PolicyStatementExtension]
Policies=InternalUseOnly

[Certsrv_Server]
RenewalKeyLength=2048
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
CRLPeriod=Days
CRLPeriodUnits=7
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0
LoadDefaultTemplates=0

[BasicConstraintsExtension]
PathLength=0
Critical=Yes

[CRLDistributionPoint]
Empty=True

[AuthorityInformationAccess]
Empty=True'

        $capolicy | Out-File -FilePath "$($env:windir)\capolicy.inf" -Encoding default -Force
        #endregion Generate a CAPolicy.inf file for "$($env:windir)\CAPolicy.inf"

        #region Install-AdcsCertificationAuthority
        try
        { 
            $null = Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA `
            -CACommonName "$Customer-Subordinate-CA" `
            -CADistinguishedNameSuffix "OU=PKI,O=$Customer,C=SE" `
            -KeyLength '2048' `
            -HashAlgorithmName 'SHA256' `
            -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' `
            -DatabaseDirectory "$($certdb.FullName)" `
            -LogDirectory "$($certlog.FullName)" `
            -OutputCertRequestFile "C:\$($Customer)-Subordinate-CA.req" `
            -OverwriteExistingKey `
            -WarningAction SilentlyContinue `
            -ErrorAction Stop `

            $null = Install-AdcsWebEnrollment -WarningAction SilentlyContinue -ErrorAction Stop -Confirm:$false
        }
        catch
        {
            Write-Warning -Message 'Unable to Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA'
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject 'Manual install AdcsCertificationAuthority with the following properties:'
            Write-Output -InputObject "
                -CACommonName '$Customer-Subordinate-CA'
                -CADistinguishedNameSuffix 'OU=PKI,O=$Customer,C=SE'
                -KeyLength '2048'
                -HashAlgorithmName 'SHA256'
                -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider'
                -DatabaseDirectory '$($certdb.FullName)'
                -LogDirectory '$($certlog.FullName)'
                -OutputCertRequestFile '$($LocalPKIPath)\$($Customer)-Subordinate-CA.req'
            -OverwriteExistingKey"
            Confirm-ToContinue
        }
        #endregion Install-AdcsCertificationAuthority

        # Declare Configuration and Domain NCs
        $null = & "$env:windir\system32\certutil.exe" -setreg ca\DSConfigDN $confignc

        # Set Validity Period for Issued Certificates 2 years
        $null = & "$env:windir\system32\certutil.exe" -setreg ca\ValidityPeriodUnits 30
        $null = & "$env:windir\system32\certutil.exe" -setreg ca\ValidityPeriod 'Months'

        # Define CRL Publication Intervals.
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLPeriodUnits 7
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLPeriod 'Days'
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLDeltaPeriodUnits 0
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLDeltaPeriod 'Days'
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLOverlapPeriodUnits 12
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLOverlapPeriod 'Hours'

        # Enable CA Audit
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\AuditFilter 127

        #region Remove any CRL Distribution Points
        $crllist = Get-CACrlDistributionPoint -ErrorAction SilentlyContinue
        foreach ($crl in $crllist)
        {
            Remove-CACrlDistributionPoint -Uri $crl.uri -Force -ErrorAction SilentlyContinue
        }
        #endregion Remove any CRL Distribution Points

        #region Remove any certificates in Authority Information Access
        $aialist = Get-CAAuthorityInformationAccess -ErrorAction SilentlyContinue
        foreach ($aia in $aialist)
        {
            Remove-CAAuthorityInformationAccess -Uri $aia.uri -Force -ErrorAction SilentlyContinue
        }
        #endregion Remove any Authority Information Access certificates

        # Set new URLs for CRL and AIA
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CRLPublicationURLs "65:$($crlpath.FullName)\%3%8.crl\n6:http://$($DomainURL)/CRL/%3%8.crl"
        $null = & "$env:windir\system32\certutil.exe" -setreg CA\CACertPublicationURLs "1:$($aiapath.FullName)\%3%4.crt\n2:http://$($DomainURL)/AIA/%3%4.crt"

        #region Create a web.config file to allow "allowDoubleEscaping"
$webconfig = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowDoubleEscaping="true" />
        </security>
    </system.webServer>
</configuration>
'@
        $webconfig | Out-File -FilePath "$($webpath.Fullname)\web.config" -Force -Encoding utf8

        # Set web.config as hidden.
        $webconfig = Get-Item "$($webpath.Fullname)\web.config" -Force
        $webconfig.Attributes = 'Hidden'
        #endregion Create a web.config file to allow "allowDoubleEscaping"

        #region Create a new website in IIS for $($webpath.Fullname) with the name PKI
        try
        {
            $null = New-WebSite -Name PKI -Port 80 -HostHeader $($DomainURL) -PhysicalPath "$($webpath.FullName)" -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "New-WebSite -Name PKI -Port 80 -HostHeader '$($DomainURL)' -PhysicalPath '$($webpath.FullName)'"
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject "Create a manual WebSite in IIS named PKI with target '$($webpath.Fullname)' and HostHeader '$($DomainURL)'"
            Confirm-ToContinue
        }

        # Enable Directory Browse for the PKI site.
        try
        {
            Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'Enabled' -Value:$true -PSPath 'IIS:\Sites\PKI' -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'Enabled' -Value:$true -PSPath 'IIS:\Sites\PKI'"
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject 'Manually enable the directory browsing option i IIS for the PKI site'
            Confirm-ToContinue
        }
        #endregion Create a new website in IIS for $($webpath.Fullname) with the name PKI

        #region View all errors
        if ($Error.Count -eq 0)
        {
            Clear-Host
        }
        else
        {
            Write-Output -InputObject 'Errors were deteted while running the script, displaying errors:'
            Start-Sleep -Milliseconds 500
            foreach ($e in $Error)
            {
                "$($e.Exception.Message)"
            }
            Write-Output -InputObject 'Does everything look OK?'
            Confirm-ToContinue
        }
        #endregion View all errors


        #region Prompt the Output for manual steps.
        Write-Output -InputObject "`nFinished installing and configuring the Subordinate Certificate Authority."
        Write-Output -InputObject 'The next steps are manual for security reasons.'

        Write-Output -InputObject "`nStep 1: Create DNS-Zone."
        Write-Output -InputObject "Create a DNS-Zone with the name $DomainURL and create a A-record pointing to this server IP ($ipaddress)"
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 2: Submit and issue the Subordinate CA certificate on the Root CA:"
        Write-Output -InputObject "Copy the request file (C:\$($Customer)-Subordinate-CA.req) to the Root CA server."
        Write-Output -InputObject "Run 'Submit a new request' in the 'CertSrv.msc' GUI."
        Write-Output -InputObject "Run 'Issue Certificate' in the 'CertSrv.msc' GUI, under 'Pending requests'."
        Write-Output -InputObject "Export the issued Subordinate CA Certificate from 'CertSrv.msc' GUI, under 'Issued certificates'. Save the export file to $($LocalPKIPath)\$($Customer)-Subordinate-CA.P7B'"
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 3: Publish a new CRL:"
        Write-Output -InputObject "On the Root Certificate Authority run 'certutil.exe -crl' to publish a new CRL to the location '$($crlpath.FullName)\$($Customer)-ROOT-CA.crl'."
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 4: Remove the 'Root CA Computername' from the AIA file(s):"
        Write-Output -InputObject "The CRT files in $($aiapath.Fullname) may contain the computername of the Root CA, remove that from the crt file including the traling underscore '_'."
        Write-Output -InputObject "Example: '$($aiapath.Fullname)\OfflineRootCA_$($Customer)-ROOT-CA.crt' should be $($aiapath.Fullname)\$($Customer)-ROOT-CA.crt"
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 5: Zip and/or copy the CRL and CRT files to the Subordinate Certificate Authority in a secure way:"
        Write-Output -InputObject 'Tip 1: Temporary enable Copy/Paste (drag-and-drop) in your virtual envoronment.'
        Write-Output -InputObject 'Tip 2: Use a USB-device to copy the files.'
        Write-Output -InputObject 'DO NOT USE ANY FORM OF NETWORK CONNECTION ON THE ROOT CERTIFICATE AUTHORITY!'
        Write-Output -InputObject 'The following files need to be copied to the Subordinate CA:'
        Write-Output -InputObject "$($LocalPKIPath)\$($Customer)-Subordinate-CA.P7B"
        Write-Output -InputObject "$($crlpath.FullName)\$($Customer)-ROOT-CA.crl"
        Write-Output -InputObject "$($aiapath.FullName)\$($Customer)-ROOT-CA.crt"
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 6: Unzip/Paste the Root CA files to the correct Subordinate CA paths:"
        Write-Output -InputObject "Move the $($Customer)-ROOT-CA.crt file to the Subordinate AIA filepath $($aiapath.Fullname)."
        Write-Output -InputObject "Move the $($Customer)-ROOT-CA.crl file to the Subordinate CRL filepath $($crlpath.Fullname)."
        Write-Output -InputObject "Move the $($Customer)-Subordinate-CA.P7B file to the Subordinate filepath $($LocalPKIPath)."
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 7: Add the Root CA the Active Directory Configuration Naming Context:"
        Write-Output -InputObject "Run: 'Certutil -dspublish -f $($Customer)-ROOT-CA.crt RootCA'"
        Write-Output -InputObject 'Starting a new Powershell process.'
        Start-Process -FilePath Powershell.exe -Verb RunAs -WorkingDirectory "$($webpath.Fullname)" -ArgumentList '-NoLogo -NoProfile -NoExit -Command "& {
            $files = Get-ChildItem -Recurse | Where-Object -FilterScript {
            $_.Name -like ''*ROOT*.crt'' -or $_.Name -like ''*ROOT*.crl''
            }
        
            Write-Output -InputObject ''Run the following commands:''
            foreach ($file in $files.FullName)
            {
            if ($file -like ''*.crt'')
            {
            Write-Output -InputObject """Certutil.exe -dspublish -f ''$file'' RootCA"""
            }
        }}"'
        $null = & "$env:windir\system32\gpupdate.exe" /force
        Confirm-ToContinue

        Write-Output -InputObject "`nStep 8: Install the Subordinate Certificate:"
        Write-Output -InputObject "Opening 'CertSrv.msc' (Right click the Subordinate CA and choose 'Install' and select the '$($LocalPKIPath)\$($Customer)-Subordinate-CA.P7B' file)."
        Write-Output -InputObject 'If prompted that the Root Certificate CA is not trusted. The Root-CA Certificate is not yet replicated through the Active Directory.'
        Write-Output -InputObject 'Press cancel and redo the Install Subordinate Certificate process after a minute or two.'
        Start-Process -FilePath certsrv.msc
        Confirm-ToContinue

        Write-Output -InputObject "`nRecommended Step: Configure a top level Group Policy for Auto enrollment:"
        Write-Output -InputObject "Open gpedit.msc and create a new Group Policy in the domain root. Example: $($Customer)-AutoEnrollment"
        Write-Output -InputObject 'Configure both Computer Configuration (CC) and User Configuration (UC).'
        Write-Output -InputObject 'CC or CU\Windows Settings\Security Settings\Public Key Policies\Certificate Services Client - Auto-Enrollment.'
        Write-Output -InputObject 'Choose "Enabled" in the drop down list. Enable(tick) both options:'
        Write-Output -InputObject 'Renew expired certificates, update pending certificate, and remove revoked certificates.'
        Write-Output -InputObject 'Update certificates that user certificate templates.'
        Start-Process -FilePath certsrv.msc
        Confirm-ToContinue
        
        try
        {
            $null = Start-Service -Name 'certsvc' -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message 'The Certificate Services (certsvc) did not start correctly.' 
            Write-Output -InputObject 'Please start the service manually.'
            Confirm-ToContinue
        }

        Start-Sleep -Seconds 3

        try
        {
            $null = Stop-Service -Name 'certsvc' -Force -ErrorAction Stop -WarningAction SilentlyContinue
        }
        catch
        {
            Write-Warning -Message 'The Certificate Services (certsvc) did not stop correctly.' 
            Write-Output -InputObject 'Please stop the service manually.'
            Confirm-ToContinue
        }

        try
        {
            $null = Start-Service -Name 'certsvc' -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message 'The Certificate Services (certsvc) did not start correctly.' 
            Write-Output -InputObject 'Please start the service manually.'
            Confirm-ToContinue
        }
        #endregion Prompt the Output for manual steps.

        #region Copy all AIA (Certificates) from the original store to the new AIA-Path
        try
        {
            Rename-Item -Path "$($env:windir)\system32\certsrv\certenroll\$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)_$($Customer)-Subordinate-CA.crt" -NewName "$($Customer)-Subordinate-CA.crt" -ErrorAction Stop
            Copy-Item -Path "$($env:windir)\system32\certsrv\certenroll\$($Customer)-Subordinate-CA.crt" -Destination $aiapath.FullName -ErrorAction Stop
        }
        catch
        {
            if ($_.CategoryInfo.Activity -eq 'Rename-Item')
            {
                Write-Warning -Message "Unable to Rename-Item $($env:windir)\system32\certsrv\certenroll\$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)_$($Customer)-Subordinate-CA.crt"
                Write-Output -InputObject "Manual rename the file to '$($Customer)-Subordinate-CA.crt'"
            }
            Write-Warning -Message "Unable to Copy-Item '$($env:windir)\system32\certsrv\certenroll\$($Customer)-Subordinate-CA.crt' to $($aiapath.FullName)"
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject "Do a manual copy of '($env:windir)\system32\certsrv\certenroll\*.crt' to '$($aiapath.FullName)'"
            Confirm-ToContinue
        }
        #region Copy all AIA (Certificates) from the original store to the new AIA-Path

        # Issue a new CRL
        $null = & "$env:windir\system32\certutil.exe" -crl

        try
        {
            Add-ScheduledPKIMaintenance -CRTFile "$($aiapath.FullName)\$($Customer)-Subordinate-CA.crt" -MaintenanceScriptFile "$($LocalPKIPath)\PKI-MaintenanceJob.ps1" -Customer $Customer -SMTPServer $SMTPServer -ToAddress $ToAddress -FromAddress $FromAddress -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message 'Unable to Add-ScheduledPKIMaintenance'
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject 'No PKI maintenance job will be created, please confirm to continue.'
            Confirm-ToContinue
        }

        try
        {
            Register-CABackup -CABackupScriptFile "$($LocalPKIPath)\Backup-CertificationAuthority.ps1" -RemoveCABackupScriptFile "$($LocalPKIPath)\Remove-CABackupFiles.ps1" -Customer $Customer -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message 'Unable to create backup jobs for the PKI environment.'
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Output -InputObject 'No PKI backup job will be created, please confirm to continue.'
            Confirm-ToContinue
        }

        Write-Output -InputObject "`nFinished installing and configuring the Subordinate Certificate Authority."
        Write-Output -InputObject 'Verify the installation in pkiview.msc.'
        Start-Process -FilePath pkiview.msc
    }
}