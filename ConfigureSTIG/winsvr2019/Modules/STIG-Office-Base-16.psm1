Function Set-Office2016BaseSTIG {

    $PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
    
    # Get Username, SID, and location of ntuser.dat for all users
    $ProfileList = gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | 
        Select  @{name="SID";expression={$_.PSChildName}}, 
                @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
                @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
    
    # Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
    $LoadedHives = gci Registry::HKEY_USERS | ? {$_.PSChildname -match $PatternSID} | Select @{name="SID";expression={$_.PSChildName}}
    
    # Get all users that are not currently logged
    $UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select @{name="SID";expression={$_.InputObject}}, UserHive, Username
    
    # Loop through each profile on the machine
    Foreach ($item in $ProfileList) {
        # Load User ntuser.dat if it's not already loaded
        IF ($item.SID -in $UnloadedHives.SID) {
            reg load HKU\$($Item.SID) $($Item.UserHive) | Out-Null
        }
    
        #####################################################################
        # This is where you can read/modify a users portion of the registry 
    
        # Example
        # New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft" -Name "Office" -Force

        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft" -Name "Office" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office" -Name "16.0" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "common" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "wef" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "osm" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "ptwatson" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "trustcenter" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\Common\" -Name "Smart Tag" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "drm" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "fixedformat" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "broadcast" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "feedback" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\wef" -Name "trustedcatalogs" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\ptwatson" -Name "PTWOptIn" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\trustcenter" -Name "TrustBar" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "DRMEncryptProperty" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "OpenXMLEncryptProperty" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "OpenXMLEncryption" -PropertyType "String" -Value "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "DefaultEncryption12" -PropertyType "String" -Value "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\common\security" -Name "AutomationSecurity" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security\trusted locations" -Name "Allow User Locations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\Common\Smart Tag" -Name "NeverLoadManifests" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\drm" -Name "RequireConnection" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\fixedformat" -Name "DisableFixedFormatDocProperties" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "EncryptDocProps" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\broadcast" -Name "disabledefaultservice" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\broadcast" -Name "disableprogrammaticaccess" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\feedback" -Name "includescreenshot" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\wef\trustedcatalogs" -Name "requireserververification" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\osm" -Name "enablefileobfuscation" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common" -Name "sendcustomerdata" -PropertyType "DWORD" -Value 0 -Force

        #####################################################################
    
        # Unload ntuser.dat        
        IF ($item.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($Item.SID) | Out-Null
        }
    }
}