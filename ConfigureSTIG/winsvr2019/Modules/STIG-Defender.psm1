Function Set-DefenderSTIG {
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft" -Name "Windows Defender" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "Exclusions" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "Spynet" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "NIS" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "Scan" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "Signature Updates" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Threats" -Name "ThreatSeverityDefaultAction" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "Rules" -Force   
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" -Name "Network Protection" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "DisableAutoExclusions" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\NIS" -Name "DisableProtocolRecognition" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableOnAccessProtection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideRealtimeScanDirection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableIOAVProtection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableBehaviorMonitoring" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableRealtimeMonitoring" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "RealtimeScanDirection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableArchiveScanning" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScheduleDay" -PropertyType "DWORD" -Value 0x0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -PropertyType "DWORD" -Value 7 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "AVSignatureDue" -PropertyType "DWORD" -Value 7 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ScheduleDay" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "5" -PropertyType "String" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "3B576869-A4EC-4529-8536-B80A7769E899" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "D3E037E1-3EB8-44C8-A917-57927947596D" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -PropertyType "String" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "4" -PropertyType "String" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "2" -PropertyType "String" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "1" -PropertyType "String" -Value 2 -Force
}
