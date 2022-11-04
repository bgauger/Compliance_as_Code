Function Set-ExcelSTIG {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    Set-ExcelUserStig
}


Function Set-ExcelUserStig {
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
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "excel" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel" -Name "Security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel" -Name "options" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\options" -Name "binaryoptions" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "filevalidation" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Workbooks" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL95Workbooks" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL9597WorkbooksandTemplates" -PropertyType "DWORD" -Value 5 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "DifandSylkFiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL2Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL2Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL3Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL3Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" -Name "EnableOnLoad" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "HtmlandXmlssFiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "DBaseFiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security" -Name "RequireAddinSig" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security" -Name "NoTBPromptUnsignedAddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" -Name "AllLocationsDisabled" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" -Name "AllowNetworkLocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\options" -Name "DefaultFormat" -PropertyType "DWORD" -Value 51 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\options\binaryoptions" -Name "fGlobalSheet_37_1" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security" -Name "AccessVBOM" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Excel\security\protectedview" -Name "DisableAttachmentsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\options" -Name "extractdatadisableui" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" -Name "DisableIntranetCheck" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "Htmlandx-m-lssFiles" -PropertyType "DWORD" -Value 2 -Force

        #####################################################################
    
        # Unload ntuser.dat        
        IF ($item.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($Item.SID) | Out-Null
        }
    }
}