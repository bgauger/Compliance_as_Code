Function Set-Office2016STIG {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "winword.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "winword.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "powerpnt.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "powerpnt.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "pptview.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "pptview.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" -Name "excel.exe" -PropertyType "DWORD" -Value 1 -Force
    Set-Office2016UserSTIG
}
Function Set-Office2016UserSTIG {

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
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "PowerPoint" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint" -Name "security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint" -Name "options" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "filevalidation" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "protectedview" -Force
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
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\Common" -Name "Security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\wef" -Name "trustedcatalogs" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0" -Name "excel" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel" -Name "Security" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel" -Name "options" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\options" -Name "binaryoptions" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "fileblock" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "trusted locations" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "protectedview" -Force
        New-Item -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\excel\Security" -Name "filevalidation" -Force
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
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\fileblock" -Name "OpenInProtectedView" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation" -Name "EnableOnLoad" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "RequireAddinSig" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "notbpromptunsignedaddin" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations" -Name "AllLocationsDisabled" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations" -Name "AllowNetworkLocations" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\options" -Name "DefaultFormat" -PropertyType "DWORD" -Value 27 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security" -Name "AccessVBOM" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview" -Name "DisableAttachmentsInPV" -PropertyType "DWORD" -Value 0 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\powerpoint\security" -Name "VBAWarnings" -PropertyType "DWORD" -Value 2 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -PropertyType "DWORD" -Value 1 -Force
        New-ItemProperty -Path "registry::HKEY_USERS\$($Item.SID)\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview" -Name "DisableIntranetCheck" -PropertyType "DWORD" -Value 0 -Force
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