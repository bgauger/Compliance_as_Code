Function Copy-SiteWebConfigBackup {
    $servername = $env:computername
    $backupname = "$servername-$datestamp-iis-Site"
    Backup-WebConfiguration -name "$backupname" -ea Stop
}

Function Set-V218735 {
   Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "mode" -value "InProc" -ea stop
}

Function Set-V218736 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "cookieless" -value "UseCookies" -ea stop
}

Function Set-V218737 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
}

Function Set-V218738 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
}

Function Set-V218739 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logTargetW3C" -value "File,ETW" -ea stop
}

Function Set-V218740 {
    $flags = "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value $flags -ea stop
}

Function Set-V218741 {
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_connection"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_connection';sourceName='Connection';sourceType='RequestHeader'}
    }  
    
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_warning"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_warning';sourceName='Warning';sourceType='RequestHeader'}
    }
}

Function Set-V218742 {
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

Function Set-V218743 {
    $mime = Get-WebConfigurationProperty -filter "//staticContent/mimeMap" -Name fileExtension | where-object{$_.value -eq '.exe' -or $_.value -eq '.dll' -or $_.value -eq '.com' -or $_.value -eq '.bat' -or $_.value -eq '.csh'}
    Foreach ($mval in $mime.value){
        Remove-WebConfigurationProperty -filter system.webServer/staticContent -Name "." -AtElement @{fileExtension=$mval}
        }
}

Function Set-V218749 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslRequireCert" -ea stop
}

Function Set-V218751 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "mode" -value "InProc" -ea stop
}

Function Set-V218753 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl" -value 4096 -ea stop
}

Function Set-V218754 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength" -value 30000000 -ea stop
}

Function Set-V218755 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString" -value 2048 -ea stop
}

Function Set-V218756 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value "False" -ea stop
}

Function Set-V218757 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value "False" -ea stop
}

### Function Set-V218758 {
###     Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value "False" -ea stop
### }

Function Set-V218759 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/directoryBrowse" -name "enabled" -value "False" -ea stop
}

Function Set-V218760 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly" -ea stop
}

Function Set-V218761 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/compilation" -name "debug" -value "False" -ea stop
}

Function Set-V218762 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -name "idleTimeout" -value "00:20:00" -ea stop
}

Function Set-V218763 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "timeout" -value "00:15:00" -ea stop
}

Function Set-V218765 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "period" -value "Daily" -ea stop
}

Function Set-V218768 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl128" -ea stop
}

Function Set-V218769 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/asp/session" -name "keepSessionIdSecure" -value "True" -ea stop
}

Function Set-V218770 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/httpCookies" -name "requireSSL" -value "True" -ea stop
}

Function Set-V218775 {
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

Function Set-AdditianalSettings {
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

Function Set-IISSiteVIDs {
    Set-V218735
    Set-V218736
    Set-V218737
    Set-V218738
    Set-V218739
    Set-V218740
    Set-V218741
    Set-V218742
    Set-V218743
    Set-V218749
    Set-V218751
    Set-V218753
    Set-V218754
    Set-V218755
    Set-V218756
    Set-V218757
    Set-V218758
    Set-V218759
    Set-V218760
    Set-V218761
    Set-V218762
    Set-V218763
    Set-V218765
    Set-V218768
    Set-V218769
    Set-V218770
    Set-V218775
    Set-AdditianalSettings
}

Function Set-IISSiteSTIG {
    New-PSDrive -name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    Copy-SiteWebConfigBackup
    Set-IISSiteVIDs
    iisreset
}

Set-IISSiteSTIG