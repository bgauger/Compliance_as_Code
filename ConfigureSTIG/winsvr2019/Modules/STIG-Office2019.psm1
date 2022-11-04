Function Set-Office2019STIG {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\Common\" -Name "COM Compatibility" -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\office\16.0\" -Name "lync" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_SAFE_BINDTOOBJECT" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_UNC_SAVEDFILECHECK" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_VALIDATE_NAVIGATE_URL" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_WEBOC_POPUPMANAGEMENT" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_ZONE_ELEVATION" -Force
    New-Item -Path "HKLM:\Software\Policies\Microsoft\OneDrive\" -Name "AllowTenantList" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_ADDON_MANAGEMENT" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_MIME_HANDLING" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_SECURITYBAND" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_LOCALMACHINE_LOCKDOWN" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_MIME_SNIFFING" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_VALIDATE_NAVIGATE_URL" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_OBJECT_CACHING" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_ZONE_ELEVATION" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_RESTRICT_ACTIVEXINSTALL" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_RESTRICT_FILEDOWNLOAD" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_UNC_SAVEDFILECHECK" -Force
    New-Item -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\" -Name "FEATURE_WINDOW_RESTRICTIONS" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\Common\COM Compatibility" -Name "COMMENT" -PropertyType "String" -Value "Block all Flash activation" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\office\16.0\lync" -Name "enablesiphighsecuritymode" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\office\16.0\lync" -Name "disablehttpconnect" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\office\16.0\lync" -Name "savepassword" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "groove.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "mspub.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" -Name "groove.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" -Name "groove.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "groove.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name " mspub.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name "groove.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList" -Name "1111-2222-3333-4444" -PropertyType "String" -Value "1111-2222-3333-4444" -Force
    Set-Office2019STIGSub
    Set-Office2019UserSTIG 
}

Function Set-Office2019STIGSub {
    $app = @( 'excel.exe','exprwd.exe','groove.exe','HelpPane.exe','msaccess.exe','mse7.exe','mspub.exe','onenote.exe','outlook.exe','powerpnt.exe','pptview.exe','prevhost.exe','spdesign.exe','visio.exe','winproj.exe','winword.exe','wmplayer.exe' )
    Write-Host $app
    Foreach ($aval in $app) {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_HANDLING" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_SECURITYBAND" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_LOCALMACHINE_LOCKDOWN" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_SNIFFING" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_VALIDATE_NAVIGATE_URL" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_OBJECT_CACHING" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_ZONE_ELEVATION" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\software\microsoft\internet explorer\main\featurecontrol\FEATURE_UNC_SAVEDFILECHECK" -Name $aval -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $aval -PropertyType "DWORD" -Value 1 -Force
    }
}


Function Set-Office2019UserSTIG {

    $PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
    
    # Get Username, SID, and location of ntuser.dat for all users
    $ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | 
        Select-Object  @{name="SID";expression={$_.PSChildName}}, 
                @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
                @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
    
    # Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
    $LoadedHives = Get-ChildItem Registry::HKEY_USERS | Where-Object {$_.PSChildname -match $PatternSID} | Select-Object @{name="SID";expression={$_.PSChildName}}
    
    # Get all users that are not currently logged
    $UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select-Object @{name="SID";expression={$_.InputObject}}, UserHive, Username
    
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

        

        
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\access\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\access\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\" -Name "" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\" -Name "portal" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\" -Name "toolbars" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "access" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "excel" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "infopath" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "outlook" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "powerpoint" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "project" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "publisher" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "visio" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars" -Name "word" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\" -Name "trustcenter" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\common\" -Name "smart tag" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\VBA\Security" -Name "LoadControlsInForms" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\excel\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\" -Name "external content" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\" -Name "filevalidation" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\" -Name "internet" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\" -Name "options" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\options\" -Name "binaryoptions" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\" -Name "rpc" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\options\" -Name "general" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\options\" -Name "mail" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\ms project\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\ms project\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security\" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security\" -Name "filevalidation" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security\" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\common\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher\" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security\" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\" -Name "filevalidation" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\" -Name "OneDrive" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\access\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\access\security" -Name "NoTBPromptUnsignedAddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\access\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\access\security\trusted locations" -Name "allownetworklocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security" -Name "macroruntimescanscope" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\common\security" -Name "DRMEncryptProperty" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\portal" -Name "linkpublishingdisabled" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\access" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\excel" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\infopath" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\outlook" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\powerpoint" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\project" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\publisher" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\visio" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\toolbars\word" -Name "noextensibilitycustomizationfromdocument" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security" -Name "UFIControls" -PropertyType "DWORD" -Value 6 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\Common\Security" -Name "AutomationSecurity" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\trustcenter" -Name "automationsecuritypublisher" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security" -Name "defaultencryption12" -PropertyType "String" -Value "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security" -Name "OpenXMLEncryption" -PropertyType "String" -Value "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\16.0\common\security\trusted locations" -Name "allow user locations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\policies\microsoft\office\common\smart tag" -Name "neverloadmanifests" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\VBA\Security" -Name "LoadControlsInForms" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" -Name "AllowNetworkLocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\excel\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\external content" -Name "disableddeserverlaunch" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\external content" -Name "disableddeserverlookup" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "DBaseFiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "DifandSylkFiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL2Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL2Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL3Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL3Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Macros" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Workbooks" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "XL4Worksheets" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "xl9597workbooksandtemplates" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" -Name "htmlandxmlssfiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\options" -Name "extractdatadisableui" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\options\binaryoptions" -Name "fupdateext_78_1" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\internet" -Name "donotloadpictures" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\options" -Name "disableautorepublish" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\options" -Name "disableautorepublishwarning" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security" -Name "extensionhardening" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security" -Name "excelbypassencryptiedmacrosscan" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\filevalidation" -Name "enableonload" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security" -Name "webservicefunctionwarnings" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\security\external content" -Name "enableblockunsecurequeryfiles" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\protectedview" -Name "enabledatabasefileprotectedview" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\protectedview" -Name "DisableInternetFilesInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\protectedview" -Name "DisableUnsafeLocationsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Excel\security\filevalidation" -Name "openinprotectedview" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Excel\security\filevalidation" -Name "DisableEditFromPV" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\excel\security\protectedview" -Name "DisableAttachmentsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "authenticationservice" -PropertyType "DWORD" -Value 16 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\rpc" -Name "enablerpcencryption" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "publicfolderscript" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "sharedfolderscript" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\options\general" -Name "msgformat" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\options\mail" -Name "junkmailprotection" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "allowactivexoneoffforms" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook" -Name "disallowattachmentcustomization" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\options\mail" -Name "Internet" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "publishtogaldisabled" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "minenckey" -PropertyType "DWORD" -Value 168 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "warnaboutinvalid" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "usecrlchasing" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "adminsecuritymode" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "allowuserstolowerattachments" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "ShowLevel1Attach" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\outlook\security" -Name "EnableOneOffFormScripts" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoomcustomaction" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoomaddressbookaccess" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "PromptOOMFormulaAccess" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoomsaveas" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoomaddressinformationaccess" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoommeetingtaskrequestresponse" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "promptoomsend" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" -Name "JunkMailEnableLinks" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\outlook\security" -Name "level" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\ms project\security\trusted locations" -Name "allownetworklocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\ms project\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\ms project\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security" -Name "runprograms" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\powerpoint\security\fileblock" -Name "binaryfiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "PowerPointBypassEncryptedMacroScan" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation" -Name "EnableOnLoad" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\powerpoint\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview" -Name "DisableInternetFilesInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview" -Name "DisableAttachmentsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview" -Name "DisableUnsafeLocationsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation" -Name "openinprotectedview" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation" -Name "DisableEditFromPV" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations" -Name "AllowNetworkLocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\common\security" -Name "automationsecuritypublisher" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher\security" -Name "RequireAddinSig" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher\security" -Name "NoTBPromptUnsignedAddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\publisher" -Name "PromptForBadFiles" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security\trusted locations" -Name "allownetworklocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\visio\security\fileblock" -Name "visio2000files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\visio\security\fileblock" -Name "visio2003files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\visio\security\fileblock" -Name "visio50andearlierfiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\visio\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security" -Name "WordBypassEncryptedMacroScan" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\protectedview" -Name "disableinternetfilesinpv" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\protectedview" -Name "disableunsafelocationsinpv" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation" -Name "openinprotectedview" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\protectedview" -Name "disableattachmentsinpv" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word2Files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "Word2000Files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "word2003files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "word2007files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "word60files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "word95files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "word97files" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security\fileblock" -Name "wordxpfiles" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\trusted locations" -Name "allownetworklocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\Microsoft\office\16.0\word\security" -Name "vbawarnings" -PropertyType "DWORD" -Value 3 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\software\policies\microsoft\office\16.0\word\security\filevalidation" -Name "enableonload" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\OneDrive" -Name "DisablePersonalSync" -PropertyType "DWORD" -Value 1 -Force



        #####################################################################
    
        # Unload ntuser.dat        
        IF ($item.SID -in $UnloadedHives.SID) {
            ### Garbage collection and closing of ntuser.dat ###
            [gc]::Collect()
            reg unload HKU\$($Item.SID) | Out-Null
        }
    }
}