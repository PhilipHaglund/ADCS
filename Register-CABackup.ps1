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
        Register-CABackup -CABackupScriptFile 'C:\PKI\Backup-CertificationAuthority.ps1' -RemoveCABackupScriptFile 'C:\PKI\Remove-CABackupFiles.ps1' -Company Contoso

        Creates and register two Scheduled Tasks each containing a Powershell script action 'C:\PKI\Backup-CertificationAuthority.ps1' / 'C:\PKI\Remove-CABackupFiles.ps1'.
        
        .INPUTS
        IO.FileInfo
        string
    
        .NOTES
        Created on:     2017-01-11 12:13
        Created by:     Philip Haglund
        Organization:   Gonjer.com
        Filename:       Register-CABackup
        Version:        0.2
        Requirements:   Powershell 3.0
        Changelog:      2017-01-11 12:13 - Creation of script.
                        2017-01-20 15:00 - Typo corrections and bugfixes.
                        

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

        # Company name that belongs to the Certificate Authority Name.
        [Parameter(
                Mandatory = $true,
                HelpMessage = 'Company name that will belong in the Certificate Authority Name.'
        )]
        [string]$Company
    )
    begin
    {
        #region Backupscript-scriptblock
        $backupscript = {            
        [cmdletbinding()]
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
            $tasktrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At (Get-Date -Date 18:00) -WeeksInterval 1 -ErrorAction Stop
            $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest -ErrorAction Stop
            $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd -ErrorAction Stop
            $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every friday at 18:00.' -ErrorAction Stop

            Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Company) - Backup PKI" -Force -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Unable to create a ScheduledTask containing '$($Company) - Backup PKI' - $($_.Exception.Message)"
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
            $tasktrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At (Get-Date -Date 22:00) -WeeksInterval 1 -ErrorAction Stop
            $taskprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest -ErrorAction Stop
            $tasksettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -Hidden -StartWhenAvailable -WakeToRun -DisallowHardTerminate -DontStopOnIdleEnd -ErrorAction Stop
            $scheduledtask = New-ScheduledTask -Action $taskaction -Trigger $tasktrigger -Principal $taskprincipal -Settings $tasksettings -Description 'Automatically created by Zetup - Runs every sunday at 22:00.' -ErrorAction Stop

            Register-ScheduledTask -InputObject $scheduledtask -TaskName "$($Company) - Remove PKI Backup files" -Force -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message "Unable to create a ScheduledTask containing '$($Company) - Remove PKI Backup files' - $($_.Exception.Message)"
            Write-Output -InputObject 'Contact your PKI Administrator!'
            return
        }
        #endregion Create RemoveCABackupScriptFile Scheduled Task        
    }
}