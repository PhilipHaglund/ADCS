<#
        .SYNOPSIS
        Installs the Subordinate Certificate Authority role and configures it.
    
        .DESCRIPTION
        Script developed for to install a Subordinate Certificate Authority when a Root (Offline) Certificate Authority is already installed.
        The configuration uses certutil.exe to modify the CA settings.
        Tested on Windows Server 2012R2.

        .EXAMPLE
        ADCS_SubordinateCA.ps1 -Customer DEMO -DomainURL pki.demo.com

        This will install the install and configure the Certificate Authority Service with the CA name "Contoso-Subordinate-CA".
        It will create the PKI folder in the default location ("$env:SystemDrive\PKI").
        The PKI folder contains the Database and paths for AIA and CRL.
        A Web Virtual Directory will be created with the name PKI mapped to "$env:SystemDrive\PKI\Web"

        This will install the install and configure the Certificate Authority Service with the CA name "Demo-Subordinate-CA".

        .EXAMPLE
        ADCS_SubordinateCA.ps1 -Customer Contoso -DomainURL pki.demo.com -LocalPKIPath E:\CALocation

        This will install the install and configure the Certificate Authority Service with the CA name "Contoso-Subordinate-CA".
        It will create a folder named CALocation in E:\.
        The PKI folder contains the Database and paths for AIA and CRL.
        A Web Virtual Directory will be created with the name PKI mapped to "E:\CALocation\Web"
            
        .NOTES
        Created on:     2016-05-11 09:15
        Created by:     Philip Haglund
        Organization:   Gonjer.com for Zetup AB
        Filename:       ADCS_SubordinateCA.ps1
        Version:        1.4
        Requirements:   Powershell 4.0 (Module: NetTCPIP, ServerManager)
        Changelog:      2016-05-11 09:15 - Creation of script
                        2016-09-19 16:25 - Removed LDAP paths CRL: "\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10" AIA: \n3:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11
                        2016-09-20 09:10 - Removed SMB Share requirements.
                        2016-10-07 15:21 - Completly changed the prompt text for the manual steps. Minor bugfixes and corrections based on PSSharper.
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
    [string]$LocalPKIPath = "$env:SystemDrive\PKI"
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
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no, $cancel)
        
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
            break
        }
        #endregion Install Windowsfeature ADCS-Cert-Authority, Adcs-Web-Enrollment
        
        #region Create directories
        $certdb = New-Item -Path "$($LocalPKIPath)\Database\CertDB" -ItemType Directory -Force
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
RenewalValidityPeriodUnits=10
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
            $install = Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA `
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

        # Set Validity Period for Issued Certificates 5 years
        $null = & "$env:windir\system32\certutil.exe" -setreg ca\ValidityPeriodUnits 5
        $null = & "$env:windir\system32\certutil.exe" -setreg ca\ValidityPeriod 'Years'

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
            $Error.ForEach{"$($_.Exception.Message)`n"}
            Write-Output -InputObject 'Done?'
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
        Write-Output -InputObject "If prompted that the Root Certificate CA is not trusted, press cancel and redo the Install process."
        Start-Process -FilePath certsrv.msc
        Confirm-ToContinue
        
        try
        {
            Start-Service -Name 'certsvc' -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop
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
            Start-Service -Name 'certsvc' -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop
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

        Write-Output -InputObject "`nFinished installing and configuring the Subordinate Certificate Authority."
        Write-Output -InputObject 'Verify the installation in pkiview.msc.'
        Start-Process -FilePath pkiview.msc
    }
}
end
{

}