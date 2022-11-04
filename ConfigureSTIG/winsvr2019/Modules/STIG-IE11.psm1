Function Set-IE11STIG {
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnBadCertRecving" /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria" /v "State" /t REG_DWORD /d 146432 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1201" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1406" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1804" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1607" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1606" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1407" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A00" /t REG_DWORD /d 65536 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1C00" /t REG_DWORD /d 65536 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "270C" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1C00" /t REG_DWORD /d 65536 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "270C" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2708" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2709" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2708" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "270C" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "270C" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" /v "BlockNonAdminActiveXInstall" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2301" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2301" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1201" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1201" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" /v "RunThisTimeEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" /v "VersionCheckEnabled" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120c" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1001" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120c" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "140C" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1004" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "140C" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\IEDevTools" /v "Disabled" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1201" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1200" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1405" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1803" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1406" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1608" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1802" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1804" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1607" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1606" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1400" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1407" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1A00" /t REG_DWORD /d 196608  /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" /v "DaysToKeep" /t REG_DWORD /d 40 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_zones_map_edit" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_options_edit" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_HKLM_only" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Security" /v "DisableSecuritySettingsCheck" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Download" /v "RunInvalidSignatures" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "yes" /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "UNCAsIntranet" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2102" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2102" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1209" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2200" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "270C" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1C00" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2402" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2402" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2500" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2500" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1809" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1809" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2101" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2101" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2000" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2200" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2004" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2001" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1402" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "Use FormSuggest" /t REG_SZ /d "no" /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoCrashDetection" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" /v "ClearBrowsingHistoryOnExit" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" /v "CleanHistory" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" /v "EnableInPrivateBrowsing" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1206" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "160A" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "explorer.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120b" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "iexplore.exe" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1409" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1206" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "160A" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1806" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120b" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1409" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "(Reserved)" /t REG_SZ /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2103" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2004" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2001" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1209" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2103" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableEPMCompat" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2709" /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d "PMEM" /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d 800 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableSSL3Fallback" /t REG_DWORD /d 0 /f
}