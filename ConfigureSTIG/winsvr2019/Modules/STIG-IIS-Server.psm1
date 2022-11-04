 Function Copy-ServerWebConfigBackup {
    $servername = $env:computername
    $backupname = "$servername-$datestamp-iis-Server"
    Backup-WebConfiguration -name "$backupname" -ea Stop
 }

Function Set-V218785 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,Method,UriQuery,Referer"
}

Function Set-V218786 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logTargetW3C" -value "File,ETW"
}

Function Set-V218788 {
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_connection"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_connection';sourceName='Connection';sourceType='RequestHeader'}
    }  
    
    If (!(Get-WebConfigurationProperty -pspath MACHINE/WEBROOT/APPHOST -filter system.applicationHost/sites/siteDefaults/logFile/CustomFields -name collection[logfieldname="log_warning"])){
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='log_warning';sourceName='Warning';sourceType='RequestHeader'}
    }
}
Function Set-V218789 {
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

Function Set-V218790 {
    $logfilesdir = "C:\inetpub\logs"

    If (test-path $logfilesdir){
        takeown /f $logfilesdir /A /R
        icacls $logfilesdir /grant administrators:F /t /c
        icacls $logfilesdir /grant system:F /t /c
        remove-item $logfilesdir -recurse
    }
}

Function Set-V218795 {
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

Function Set-V218798 {
    $mime = Get-WebConfigurationProperty -filter "//staticContent/mimeMap" -Name fileExtension | where-object{$_.value -eq '.exe' -or $_.value -eq '.dll' -or $_.value -eq '.com' -or $_.value -eq '.bat' -or $_.value -eq '.csh'}
    Foreach ($mval in $mime.value){
        Remove-WebConfigurationProperty -filter system.webServer/staticContent -Name "." -AtElement @{fileExtension=$mval}
        }
}

Function Set-V218804 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "cookieless" -value "UseCookies"
}

Function Set-V218805 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "timeout" -value "00:20:00"
}

Function Set-V218807 {
    Set-WebConfigurationProperty -filter /system.web/machineKey -PSPath "MACHINE/WEBROOT" -name validation -value 'HMACSHA256' -ea Stop
}

Function Set-V218808 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/directoryBrowse" -name "enabled" -value "True"
}

Function Set-V218810 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly"
}

Function Set-V218814 {
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

Function Set-V218815 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "period" -value "Daily" 
}

Function Set-V218816 {
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

Function Set-V218820 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/asp/session" -name "keepSessionIdSecure" -value "True"
}

Function Set-V218821 {
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

Function Set-V218826 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/limits" -name "maxConnections" -value 4294967295
}

Function Set-V218827 {
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "enabled" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "max-age" -value 31536000
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "includeSubDomains" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "redirectHttpToHttps" -value "True"
}

Function Set-V241788 {
    New-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\HTTP\Parameters" -Name DisableServerHeader -PropertyType DWORD -Value 1 -ea SilentlyContinue
}

Function Set-IISServerVIDs {
    Set-V218785
    Set-V218786
    Set-V218788
    Set-V218789
    Set-V218790
    Set-V218795
    Set-V218798
    Set-V218804
    Set-V218805
    Set-V218807
    Set-V218808
    Set-V218810
    Set-V218814
    Set-V218815
    Set-V218816
    Set-V218820
    Set-V218821
    Set-V218826
    Set-V218827
    Set-V241788
}

Function Set-IISServerSTIG {
    New-PSDrive -name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    Copy-ServerWebConfigBackup
    Set-IISServerVIDs
    iisreset
}

Set-IISServerSTIG