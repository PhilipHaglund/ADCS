function Edit-Certdat
{
    <#
        .SYNOPSIS
        Edits the Certdat.inc file located in under WinDir\System32\certsrv (C:\Windows\System32\CertSrv).
        
        .DESCRIPTION
        Edits the Certdat.inc file based on the input to match the company properties.
        Will modify the following set of variables:

        sDefaultCompany=""
	    sDefaultOrgUnit=""
	    sDefaultLocality=""
	    sDefaultState=""
	    sDefaultCountry=""	   
	    sServerDisplayName=""
                
        .EXAMPLE
        Edit-Certdat -Company 'Contoso' -City 'Gothenburg' -State VG
        
        This will modify the file 'C:\Windows\system32\certsrv\certdat.inc' and change the following variables:

        sDefaultCompany="Contoso"
	    sDefaultOrgUnit="IT"
	    sDefaultLocality="Gothenburg"
	    sDefaultState="VG"
	    sDefaultCountry="Sweden"	   
	    sServerDisplayName="Contoso - Certificate Authority"
        
        .EXAMPLE
        Edit-Certdat -CertdatFile 'E:\Windows\system32\certsrv\certdat.inc' -Company 'Contoso DK' -OrgUnit 'Information Technology' -City 'Copenhagen' -State 'Hovedstaden' -Country 'Denmark'
        
        This will modify the file 'E:\Windows\system32\certsrv\certdat.inc' and change the following variables:

        sDefaultCompany="Contoso DK"
	    sDefaultOrgUnit="Information Technology"
	    sDefaultLocality="Copenhagen"
	    sDefaultState="Hovedstaden"
	    sDefaultCountry="Denmark"	   
	    sServerDisplayName="Contoso DK - Certificate Authority"
        
        .INPUTS
        IO.FileInfo
        String
        
        .NOTES
        Created on:     2017-01-20 13:48
        Created by:     Philip Haglund
        Organization:   Gonjer.com
        Filename:       Edit-Certdat.ps1
        Version:        0.1
        Requirements:   Powershell 3.0
        Changelog:      2017-01-20 13:48 - Creation of script.
                        
        
        .LINK
        https://www.gonjer.com
    #>

    [cmdletbinding()]
    param (
        # Specify a fully qualified file path for the certdat.inc file.
        # Example: C:\Windows\system32\certsrv\certdat.inc
        [Parameter(
                    ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.inc$')]
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
        [Alias('dat')]
        [IO.FileInfo]$CertdatFile = "$env:windir\system32\certsrv\certdat.inc",

        # A Company name used to populate the certdat.inc file with correct information.
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'Contoso'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Company,

        # An organizational unit used to populate the certdat.inc file with correct information.
        # Example: IT
        [Parameter(
                ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [string]$OrgUnit = 'IT',

        # A city used to populate the certdat.inc file with correct information.
        # Example: Gothenburg
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'Gothenburg'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$City,

        # A state used to populate the certdat.inc file with correct information.
        # Example: VG
        [Parameter(
                Mandatory = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = 'VG'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$State,

        # A state used to populate the certdat.inc file with correct information.
        # Example: VG
        [Parameter(
                ValueFromPipelineByPropertyName = $True                
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Country = 'Sweden'
    )
    begin
    {
        $warningtext = 'Will not create modify the Web Enrollment page.'

        try
        {
            $content = Get-Content -Path $CertdatFile -ErrorAction Stop
        }
        catch
        {
            Write-Error -Message "Unable to open the file $($CertdatFile) - $($_.Exception.Message)"
            Write-Warning -Message $warningtext
            break
        }       
    }
    process
    {
        # A set or variables containing the regex relace strings
        $sdefaultcompany    = 'sDefaultCompany\=\"(.+|)\"', "sDefaultCompany=`"$Company`""
        $sdefaultorgUnit    = 'sDefaultOrgUnit\=\"(.+|)\"', "sDefaultOrgUnit=`"$OrgUnit`""
        $sdefaultlocality   = 'sDefaultLocality\=\"(.+|)\"', "sDefaultLocality=`"$City`""
        $sdefaultstate      = 'sDefaultState\=\"(.+|)\"', "sDefaultState=`"$State`""
        $sdefaultcountry    = 'sDefaultCountry\=\"(.+|)\"', "sDefaultCountry=`"$Country`""
        $sserverdisplayname = 'sServerDisplayName\=\"(.+|)\"', "sServerDisplayName=`"$Company - Certificate Authority`""

        $modcontent = $content -replace $sdefaultcompany -replace $sdefaultorgUnit -replace $sdefaultlocality -replace $sdefaultstate -replace $sdefaultcountry -replace $sserverdisplayname

        try
        {
            $modcontent | Set-Content -Path $CertdatFile -Force -Encoding UTF8
        }
        catch
        {
            Write-Error -Message "Unable to modiofy the file $($CertdatFile) - $($_.Exception.Message)"
            Write-Warning -Message $warningtext
            break
        }
    }
}