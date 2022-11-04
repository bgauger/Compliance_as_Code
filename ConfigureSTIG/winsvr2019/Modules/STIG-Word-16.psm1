Function Set-WordSTIG {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "winword.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "winword.exe" -PropertyType "DWORD" -Value 1 -Force
    Set-WordUserSTIG
}

Function Set-WordUserSTIG {

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
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "word" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word" -Name "options" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "filevalidation" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\" -Name "research" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\research" -Name "translation" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\filevalidation" -Name "EnableOnLoad" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "RequireAddinSig" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "NoTBPromptUnsignedAddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations" -Name "AllLocationsDisabled" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations" -Name "AllowNetworkLocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\options" -Name "DefaultFormat" -PropertyType "String" -Value "" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "AccessVBOM" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation" -Name "openinprotectedview" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation" -Name "DisableEditFromPV" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\protectedview" -Name "DisableAttachmentsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\options" -Name "DontUpdateLinks" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "VBAWarnings" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\research\translation" -Name "useonline" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word2Files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word2000Files" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word60Files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word95Files" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word97Files" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "WordXPFiles" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Word\security\protectedview" -Name "DisableIntranetCheck" -PropertyType "DWORD" -Value 0 -Force

        #####################################################################
    
        # Unload ntuser.dat        
        IF ($item.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($Item.SID) | Out-Null
        }
    }
}