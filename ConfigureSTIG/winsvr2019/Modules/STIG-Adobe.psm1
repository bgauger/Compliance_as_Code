Function Set-AdobeSTIG {
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\" -Name "FeatureLockDown" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cDefaultLaunchURLPerms" -Force
    New-Item -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\" -Name "Installer" -Force
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\" -Name "Installer" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cServices" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cWebmailProfiles" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cSharePoint" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cWelcomeScreen" -Force
    New-Item -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\" -Name "cEUTLDownload" -Force
    New-Item -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\" -Name "cAdobeDownload" -Force
    New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cCloud" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityStandalone" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityInBrowser" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bProtectedMode" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iProtectedView" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iURLPerms" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iUnknownURLPerms" -PropertyType "DWORD" -Value 3 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iFileAttachmentPerms" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnableFlash" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisablePDFHandlerSwitching" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name "bAdobeSendPluginToggle" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeDocumentServices" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bTogglePrefsSync" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "iProtectedView" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleWebConnectors" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bAcroSuppressUpsell" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeSign" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name "bDisableWebmail" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name "bDisableSharePointFeatures" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name "bShowWelcomeScreen" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bUpdater" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedFolders" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedSites" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload" -Name "bLoadSettingsFromURL" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload" -Name "bLoadSettingsFromURL" -PropertyType "DWORD" -Value 0 -Force
    Set-AdobeUserSTIG
}

Function Set-AdobeUserSTIG {
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

        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name "cCloud" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\" -Name "AVGeneral" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\" -Name "cEUTLDownload" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\" -Name "cAdobeDownload" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\AVGeneral" -Name "bFIPSMode" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name "bAdobeSendPluginToggle" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload" -Name "bLoadSettingsFromURL" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload" -Name "bLoadSettingsFromURL" -PropertyType "DWORD" -Value 0 -Force
    
        #####################################################################
    
        # Unload ntuser.dat        
        IF ($item.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($Item.SID) | Out-Null
        }
    }
}            