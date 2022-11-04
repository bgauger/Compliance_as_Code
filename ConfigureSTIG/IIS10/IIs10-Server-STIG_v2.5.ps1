#######SCRIPT FOR IIS SERVER STIG#####
#
<#
.SYNOPSIS
    Applies changes to IIs 10 configuration to be STIG compliant.

.DESCRIPTION
    This powershell script applies several configuration changes to an IIs 10 configuration to meet STIG guidance.
    Script is applicable to "Microsoft IIS 10.0 Server Security Technical Implementation Guide"
    Version 2, Release: 5 Benchmark Date: 27 Jan 2022
    
.EXAMPLE
    .\IIs10-Server-STIG_v2.5.ps1

.NOTES
    Original Author:   Ben Gauger, Quantum Research International - bgauger@quantum-intl.com
    Revision History:  
    V1 - 3/15/2022 - Initial version completed

#>
#Requires -RunAsAdministrator


<#  
.SYNOPSIS
    Write-Log function
     
.PARAMETER -msg [string]
  Specifies the message to be logged
.PARAMETER -terminate [switch]  
  Used to create error log output and terminates the script
.PARAMETER -warn [switch]  
  Used to create warning output
.PARAMETER -err [switch]  
  Used to create error log output
#>

function write-log{
    param([string]$msg, [switch]$terminate, [switch]$warn, [switch]$err)

    if($terminate){
        $msg = "[$(get-date -Format HH:mm:ss)] FATAL ERROR: " + $msg
        add-content -Path $errlogfile -Value $msg
        throw $msg
    }
    elseif($err){
        $msg = "[$(get-date -Format HH:mm:ss)] ERROR: " + $msg
        add-content -Path $errlogfile -Value $msg
        Write-host $msg -ForegroundColor Red
    }
    elseif($warn){
        Write-Warning $msg
        $msg = "[$(get-date -Format HH:mm:ss)] WARNING: " + $msg
        add-content -Path $logfile -Value $msg
    }
    else{
        $msg = "[$(get-date -Format HH:mm:ss)] " + $msg
        write-host $msg
        add-content -Path $logfile -Value $msg
    }
}

function write-error{
    write-host ""
    write-host "An error has occurred! Detail to follow." -foregroundcolor red
    write-host ""
    do {
        $answer = read-host "Do you want to restore IIs configuration? (Yes/No)"
    }
    until ("yes","no" -contains $answer)
    if ($answer -eq "Yes"){
        Restore-WebConfiguration -name "$backupname" -ea SilentlyContinue
        write-host "IIs configuration "$backupname" restored." -ForegroundColor yellow
    }
    Else{
         write-host "IIs configuration not restored." -ForegroundColor yellow
    }
    write-log -terminate $_
}


# Setup log files
$scriptName = $MyInvocation.MyCommand.Name
$dateStamp = get-date -Format yyyyMMdd_HHmmss
[string]$logfile = "$scriptName`_$dateStamp.log"
[string]$errlogfile = "$scriptName`_$dateStamp`_error.log"

set-content -Path $logfile  -Value "Log started $(get-date)"
set-content -Path $errlogfile  -Value "Log started $(get-date)"

# Script variables
$servername = $env:computername
$backupname = "$servername-$datestamp-iis"
$version = "2.5"
New-PSDrive -name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

write-log -msg "$version IIS 10 Hardening Script"
write-log -msg ""

##BEGIN IIS 10 Server STIG Items
#<#Listing IIS 10 Server STIG Items not included in script as they are manual checks or vary greatly for implementations, or will be re-evaluated in next release of script
#IIST-SV-000100/ V-218784  IIST-SV-000109/ V-218787  IIST-SV-000116/ V-218791
#IIST-SV-000117/ V-218792  IIST-SV-000117/ V-218793  IIST-SV-000117/ V-218794
#IIST-SV-000117/ V-218796  IIST-SV-000117/ V-218797  IIST-SV-000125/ V-218799
#IIST-SV-000129/ V-218800  IIST-SV-000137/ V-218807  IIST-SV-000139/ V-218809	
#IIST-SV-000141/ V-218811  IIST-SV-000142/ V-218812	IIST-SV-000143/ V-218813
#IIST-SV-000148/ V-218817  IIST-SV-000149/ V-218818  IIST-SV-000151/ V-218819
#IIST-SV-000156/ V-218823  IIST-SV-000158/ V-218824	IIST-SV-000159/ V-218825	
#IIST-SV-000160/ V-228572  IIST-SV-000215/ V-241789	
#
#
##>
#
try{
    write-log -msg "Beginning backup"
    Backup-WebConfiguration -name "$backupname" -ea Stop
    write-log -msg "Backup is stored at %WINDIR%\System32\inetsrv\backup\<$backupname>"
    write-log -msg "Backup Completed"

    write-log -msg ""
    write-log -msg "Starting IIs Configuration"
}
catch{
    write-error
}

# IIST-SV-000102 / V-218785
try{
    write-log -msg "Configuring for IIST-SV-000102 / V-218785"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,Method,UriQuery,Referer"
}
catch{
    write-error
}

# IIST-SV-000103 / V-218786
try{
    write-log -msg "Configuring for IIST-SV-000103 / V-218786"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logTargetW3C" -value "File,ETW"
}
catch{
    write-error
}

# IIST-SV-000110 / V-218788
try{
    write-log -msg "Configuring for IIST-SV-000110 / V-218788"
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_connection"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_connection';sourceName='Connection';sourceType='RequestHeader'}
    }  
    
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_warning"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_warning';sourceName='Warning';sourceType='RequestHeader'}
    }
}
catch{
    write-error
}

# IIST-SV-000111 / V-218789
try{
    write-log -msg "Configuring for IIST-SV-000111 / V-218789"
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="ReqHeadUagent"])){
        Add-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name "." -value @{logFieldName='ReqHeadUagent';sourceName='User-Agent';sourceType='RequestHeader'}
    }

    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="ReqHeadAuth"])){
        Add-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name "." -value @{logFieldName='ReqHeadAuth';sourceName='Authorization';sourceType='RequestHeader'}
    }

    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="ResHeadCont-Type"])){
        Add-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name "." -value @{logFieldName='ResHeadCont-Type';sourceName='Content-Type';sourceType='ResponseHeader'}
    }

    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="ResHeadCont-Type"])){
        Add-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name "." -value @{logFieldName='HTTP_USER_AGENT';sourceName='HTTP_USER_AGENT';sourceType='ServerVariable'}
    }

}
catch{
    write-error
}

# IIST-SV-000115 / V-218790
try{
    write-log -msg "Configuring for IIST-SV-000115 / V-218790"
    $logfilesdir = "C:\inetpub\logs"

    If (test-path $logfilesdir){
        takeown /f $logfilesdir /A /R
        icacls $logfilesdir /grant administrators:F /t /c
        icacls $logfilesdir /grant system:F /t /c
        remove-item $logfilesdir -recurse
    }
    Else{
        Write-log -msg "$logfilesdir does not exist, no further action necessary."
    }
}
catch{
    write-error
}

#convert to foreach
# IIST-SV-000111 / V-218795
try{
    write-log -msg "Configuring for IIST-SV-000111 / V-218795"
    If (Test-Path "C:\Program Files\Common Files\system\msadc"){
        takeown /f 'C:\Program Files\Common Files\system\msadc' /A /R
        icacls 'C:\Program Files\Common Files\system\msadc' /grant administrators:F /t /c
        icacls 'C:\Program Files\Common Files\system\msadc' /grant system:F /t /c
        Remove-Item 'C:\Program Files\Common Files\system\msadc' -Recurse -Force
    }

    If (Test-Path "C:\Program Files (x86)\Common Files\system\msadc"){
        takeown /f 'C:\Program Files (x86)\Common Files\system\msadc' /A /R
        icacls 'C:\Program Files (x86)\Common Files\system\msadc' /grant administrators:F /t /c
        icacls 'C:\Program Files\Common Files\system\msadc' /grant system:F /t /c
        Remove-Item 'C:\Program Files (x86)\Common Files\system\msadc' -Recurse -Force
    }

    If (Test-Path "C:\inetpub\wwwroot"){
        takeown /f 'C:\inetpub\wwwroot' /A /R
        icacls 'C:\inetpub\wwwroot' /grant administrators:F /t /c
        Get-ChildItem 'C:\inetpub\wwwroot' -Include iisstart.* -Recurse | Remove-Item
    }
}
catch{
    write-error
}

# IIST-SV-000124/ V-218798
try{
    write-log -msg "Configuring for IIST-SV-000124/ V-218798"
    $mime = Get-WebConfigurationProperty -filter "//staticContent/mimeMap" -Name fileExtension | where-object{$_.value -eq '.exe' -or $_.value -eq '.dll' -or $_.value -eq '.com' -or $_.value -eq '.bat' -or $_.value -eq '.csh'}
    Foreach ($mval in $mime.value){
        Remove-WebConfigurationProperty -filter system.webServer/staticContent -Name "." -AtElement @{fileExtension=$mval}
        }
}
catch{
    write-error
}

# IIST-SV-000134/ V-218804	
try{
    write-log -msg "Configuring for IIST-SV-000134/ V-218804"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "cookieless" -value "UseCookies"
}
catch{
    write-error
}

# IIST-SV-000135/ V-218805	
try{
    write-log -msg "Configuring for IIST-SV-000135/ V-218805"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "timeout" -value "00:20:00"
}
catch{
    write-error
}

# IIST-SV-000137/ V-218807	 	
try{
    write-log -msg "Configuring for IIST-SV-000137/ V-218807"
    Set-WebConfigurationProperty -filter /system.web/machineKey -PSPath "MACHINE/WEBROOT" -name validation -value 'HMACSHA256' -ea Stop
}
catch{
    write-error
}

# IIST-SV-000138/ V-218808	 	
try{
    write-log -msg "Configuring for IIST-SV-000138/ V-218808"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/directoryBrowse" -name "enabled" -value "True"
}
catch{
    write-error
}

# IIST-SV-000140/ V-218810		 	
try{
    write-log -msg "Configuring for IIST-SV-000140/ V-218810"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly"
}
catch{
    write-error
}

# IIST-SV-000144/ V-218814	 
try{
    write-log -msg "Configuring for IIST-SV-000144/ V-218814"
    $inetpubdir = "C:\inetpub"

    If (test-path $inetpubdir){
        takeown /f $inetpubdir /A /R
        icacls $inetpubdir /grant administrators:F /t /c
        icacls $inetpubdir /grant system:F /t /c
        icacls $inetpubdir /grant trustedinstaller:F /t /c
        icacls $inetpubdir /grant 'ALL APPLICATION PACKAGES':RX /t /c
        icacls $inetpubdir /grant users:RD /t /c
    }
}
catch{
    write-error
}

# IIST-SV-000145/ V-218815	#Setting value for daily will not allow the "Do not create new log files" option to be set.
try{
    write-log -msg "Configuring for IIST-SV-000145/ V-218815"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "period" -value "Daily"
}
catch{
    write-error
}

# IIST-SV-000147/ V-218816		 
try{
    write-log -msg "Configuring for IIST-SV-000147/ V-218816"
    $inetmgrdir = "C:\Windows\System32\inetsrv\InetMgr.exe"

    If (test-path $inetmgrdir){
        takeown /f $inetpubdir /A /R
        icacls $inetmgrdir /grant 'ALL RESTRICTED APPLICATION PACKAGES':RX /t /c
        icacls $inetmgrdir /grant system:RX /t /c
        icacls $inetmgrdir /grant trustedinstaller:F /t /c
        icacls $inetmgrdir /grant 'ALL APPLICATION PACKAGES':RX /t /c
        icacls $inetmgrdir /grant users:RX /t /c
    }
}
catch{
    write-error
}

# IIST-SV-000152/ V-218820
try{
    write-log -msg "Configuring for IIST-SV-000152/ V-218820"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/asp/session" -name "keepSessionIdSecure" -value "True"
}
catch{
    write-error
}

# IIST-SV-000153/ V-218821
try{
    write-log -msg "Configuring for IIST-SV-000153/ V-218821 // IIST-SV-000154/ V-218822 (Enabling TLS 1.2 & TLS 1.3)"
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", $true)
    $newkey.CreateSubKey('SSL 2.0')
    $newkey.CreateSubKey('SSL 3.0')
    $newkey.CreateSubKey('TLS 1.1')
    $newkey.CreateSubKey('TLS 1.2')
    $newkey.CreateSubKey('TLS 1.3')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name DisabledByDefault -PropertyType DWORD -Value 0 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name DisabledByDefault -PropertyType DWORD -Value 0 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name Enabled -PropertyType DWORD -Value 1 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
}
catch{
    write-error
}

# IIST-SV-000200/ V-218826
try{
    write-log -msg "Configuring for IIST-SV-000200/ V-218826"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/limits" -name "maxConnections" -value 4294967295
}
catch{
    write-error
}

# IIST-SV-000205/ V-218827
try{
    write-log -msg "Configuring for IIST-SV-000200/ V-218826"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "enabled" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "max-age" -value 31536000
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "includeSubDomains" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "redirectHttpToHttps" -value "True"
}
catch{
    write-error
}

# IIST-SV-000210/ V-241788
try{
    write-log -msg "Configuring for IIST-SV-000210/ V-241788"
    New-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\HTTP\Parameters" -Name DisableServerHeader -PropertyType DWORD -Value 1 -ea SilentlyContinue
}
catch{
    write-error
}

# Run iisreset for settings to take effect
write-log -msg "Performing an IISReset for changes to take effect"
iisreset
write-log -msg ""
write-log -msg "IIS 10 Hardening Script complete - Version $version"