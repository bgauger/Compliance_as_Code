Function Set-ChromeSTIG {
    New-Item -Path "Registry::HKLM\Software\Policies\Google\" -Name "Chrome" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "URLBlocklist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ExtensionInstallWhitelist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ExtensionInstallBlocklist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ExtensionInstallAllowlist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "AutoplayAllowlist" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "RemoteAccessHostFirewallTraversal" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultGeolocationSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultPopupsSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist" -Name "1" -PropertyType "String" -Value "*" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" -Name "1" -PropertyType "String" -Value "oiigbmnaadbkfbmpbfijlflahbdbdgdf" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\ExtensionInstallAllowlist" -Name "1" -PropertyType "String" -Value "oiigbmnaadbkfbmpbfijlflahbdbdgdf" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" -Name "2" -PropertyType "String" -Value "gmhjclgpamdccpomoomknemhmmialaae" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\ExtensionInstallAllowlist" -Name "2" -PropertyType "String" -Value "gmhjclgpamdccpomoomknemhmmialaae" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultSearchProviderName" -PropertyType "String" -Value "Google Encrypted" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultSearchProviderSearchURL" -PropertyType "String" -Value "https://www.google.com/search?q={searchTerms}" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultSearchProviderEnabled" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "BackgroundModeEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SyncDisabled" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\URLBlocklist" -Name "1" -PropertyType "String" -Value "javascript://*" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "CloudPrintProxyEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "NetworkPredictionOptions" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SearchSuggestEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ImportSavedPasswords" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "IncognitoModeAvailability" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "EnableOnlineRevocationChecks" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SafeBrowsingProtectionLevel" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "AllowDeletingBrowserHistory" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "PromptForDownloadLocation"-PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SafeBrowsingExtendedReportingEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultWebUsbGuardSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "EnableMediaRouter" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "AutoplayAllowed" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "Enabled" -PropertyType "String" -Value "[*.]mil" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "UrlKeyedAnonymizedDataCollectionEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "WebRtcEventLogCollectionAllowed" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DeveloperToolsAvailability" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "BrowserGuestModeEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "AutofillCreditCardEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "AutofillAddressEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "ImportAutofillFormData" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "SSLVersionMin" -PropertyType "String" -Value "tls1.2" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "DefaultWebBluetoothGuardSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome" -Name "QuicAllowed" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\AutoplayAllowlist" -Name "Enabled" -PropertyType "String" -Value "[*.]mil" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Google\Chrome\AutoplayAllowlist" -Name "Enabled" -PropertyType "String" -Value "[*.]gov" -Force
}