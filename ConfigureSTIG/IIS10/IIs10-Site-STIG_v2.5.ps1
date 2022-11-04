######SCRIPT FOR IIS SITE STIG#####

<#
.SYNOPSIS
    Applies changes to IIs 10 configuration to be STIG compliant.

.DESCRIPTION
    This powershell script applies several configuration changes to an IIs 10 configuration to meet STIG guidance.
    Script is applicable to "Microsoft IIS 10.0 Site Security Technical Implementation Guide"
    Version 2, Release: 5 Benchmark Date: 27 Jan 2022
    
.EXAMPLE
    .\IIs10-Site-STIG_v2.5.ps1

.NOTES
    Original Author:      Ben Gauger, Quantum Research International - bgauger@quantum-intl.com
    Additional Authors:
    Revision History:  
    V1 - 3/17/2022 - Initial version completed

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
<#  
.SYNOPSIS
    Write-error function will present an error if there is a breakage within the script or prompt for a yes or no question.
#>
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

#BEGIN IIS 10 Server STIG Items
<#Listing IIS 10 Server STIG Items not included in script as they are manual checks or vary greatly for implementations, or will be re-evaluated in next release of script
IIST-SI-000215/ V-218744  IIST-SI-000216/ V-218745  IIST-SI-000217/ V-218746
IIST-SI-000219/ V-218748  IIST-SI-000224/ V-218752  IIST-SI-000237/ V-218764
IIST-SI-000239/ V-218766  IIST-SI-000241/ V-218767  IIST-SI-000251/ V-218771
IIST-SI-000252/ V-218772  IIST-SI-000261/ V-218779  IIST-SI-000262/ V-218780
IIST-SI-000263/ V-218781  IIST-SI-000264/ V-218782


#>
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

try{
    write-log -msg "Configuring for IIST-SI-000201/ V-218735"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "mode" -value "InProc" -ea stop
}
catch {
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000202/ V-218736"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "cookieless" -value "UseCookies" -ea stop
}
catch {
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000203/ V-218737"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
}
catch {
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000204/ V-218738"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
}
catch {
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000206/ V-218739"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logTargetW3C" -value "File,ETW" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000206/ V-218739"
    $flags = "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value $flags -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000209 / V-218741"
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

try{
    write-log -msg "Configuring for IIST-SI-000210/ V-218742"
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

try{
    write-log -msg "Configuring for IIST-SI-000214/ V-218743"
    $mime = Get-WebConfigurationProperty -filter "//staticContent/mimeMap" -Name fileExtension | where-object{$_.value -eq '.exe' -or $_.value -eq '.dll' -or $_.value -eq '.com' -or $_.value -eq '.bat' -or $_.value -eq '.csh'}
    Foreach ($mval in $mime.value){
        Remove-WebConfigurationProperty -filter system.webServer/staticContent -Name "." -AtElement @{fileExtension=$mval}
        }
}
catch{
    write-error
}

 try{
     write-log -msg "Configuring for IIST-SI-000220/ V-218749"
     Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
 }
 catch{
     write-error
 }

try{
    write-log -msg "Configuring for IIST-SI-000223/ V-218751"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "mode" -value "InProc" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000225/ V-218753"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096 -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000225/ V-218753"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096 -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000226/ V-218754"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000 -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000227/ V-218755"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048 -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000228/ V-218756"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value "False" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000229/ V-218757"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value "False" -ea stop
}
catch{
    write-error
}

### try{
###     write-log -msg "Configuring for IIST-SI-000230/ V-218758"
###     Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value "False" -ea stop
### }
### catch{
###     write-error
### }

try{
    write-log -msg "Configuring for IIST-SI-000231/ V-218759"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/directoryBrowse" -name "enabled" -value "False" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000233/ V-218760"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000234/ V-218761"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/compilation" -name "debug" -value "False" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000234/ V-218761"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/compilation" -name "debug" -value "False" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000235/ V-218762"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -name "idleTimeout" -value "00:20:00" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000236/ V-218763"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "timeout" -value "00:15:00" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000238/ V-218765"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "period" -value "Daily" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000242/ V-218768"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl128" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000244/ V-218769"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/asp/session" -name "keepSessionIdSecure" -value "True" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000246/ V-218770"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/httpCookies" -name "requireSSL" -value "True" -ea stop
}
catch{
    write-error
}

try{
    write-log -msg "Configuring for IIST-SI-000255,257-259,261 / V-218775,V-218776,V-218777,V-218778,V-218779"
    $apppools = Get-ChildItem -path IIS:\AppPools
    Foreach ($a in $apppools.name){
        Set-ItemProperty "IIS:\AppPools\$a" -name "processModel" -Value @{idleTimeout="00:20:00";pingingEnabled="True"} -ea Stop
        #Setting some arbitrary values on next line for STIG compliance, please adjust if needed.
        #Set-ItemProperty "IIS:\AppPools\$a" -name "recycling.periodicRestart" -value @{requests=250000;memory=2097152;privateMemory=2097152} -ea Stop
        Set-ItemProperty "IIS:\AppPools\$a" -name "recycling.periodicRestart" -value @{requests=250000;memory=0;privateMemory=2097152} -ea Stop
        Set-ItemProperty "IIS:\AppPools\$a" -name "recycling" -value @{logEventOnRecycle="Time,Schedule,Memory,PrivateMemory"} -ea Stop
        Set-ItemProperty "IIS:\AppPools\$a" -name "queueLength" -Value 1000 -ea Stop
        Set-ItemProperty "IIS:\AppPools\$a" -name "failure" -Value @{rapidFailProtection="True";rapidFailProtectionInterval="00:05:00"} -ea Stop
        [string] $NumberofApplications = (Get-WebConfigurationProperty "/system.applicationHost/sites/site/application[@applicationPool='$a']" "machine/webroot/apphost" -name path).Count
        If ($NumberofApplications -gt 1){
            #Write-log -msg "AppPool name: $a has $NumberofApplications applications"
            Write-host "$a has more than 1 Application, this is an open finding!"
        }
    }
}
catch{
    write-error
}

 try{
     write-log -msg "Configuring for"
     Foreach ($w in $websites.name){
         Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering/requestLimits -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name maxUrl -value 4096 -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering/requestLimits -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name maxAllowedContentLength -value 30000000 -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering/requestLimits -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name maxQueryString -value 2048 -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name AllowHighBitCharacters -value False -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name AllowDoubleEscaping -value False -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name enabled -value False -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/httpErrors -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name errorMode -value DetailedLocalOnly -ea Stop
         Set-WebConfigurationProperty -filter /system.web/compilation -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name debug -value False -ea Stop
         Set-WebConfigurationProperty -filter /system.web/sessionState -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name timeout -value 00:15:00 -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/asp/session -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name keepSessionIdSecure -value 'True' -ea Stop
         Set-WebConfigurationProperty -filter /system.web/httpCookies -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name requireSSL -value 'True' -ea Stop
         Set-WebConfigurationProperty -filter /system.web/sessionState -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name compressionEnabled -value 'False' -ea Stop
         Set-WebConfigurationProperty -filter /system.web/httpCookies -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name httpOnlyCookies -value 'True' -ea Stop
         Set-WebConfigurationProperty -filter /system.web/httpCookies -PSPath "MACHINE/WEBROOT/APPHOST/$w" -name requireSSL -value 'True' -ea Stop
         Set-WebConfigurationProperty -filter /system.webServer/security/access -name sslFlags -value 'Ssl,SslRequireCert,Ssl128' -PSPath "MACHINE/WEBROOT/APPHOST/$w" -ea Stop
         Clear-WebConfiguration -Filter "/system.web/authorization/allow[@users='*' and @roles='' and @verbs='']" -PSPath "MACHINE/WEBROOT/APPHOST/$w" -ea stop
         Add-WebConfiguration -Filter /system.web/authorization -Value @{accesstype = "Allow";Users = "*"} -PSPath "MACHINE/WEBROOT/APPHOST/$w" -ea stop
     }
 }
 catch{
     write-error
 }

# Run iisreset for settings to take effect
write-log -msg "Performing an IISReset for changes to take effect"
iisreset
write-log -msg ""
write-log -msg "IIS 10 Hardening Script complete - Version $version"