Function Set-FirewallSTIG {
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft" -Name "DomainProfile" -Force
    New-Item -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "Logging" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft" -Name "PrivateProfile" -Force
    New-Item -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "Logging" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft" -Name "PublicProfile" -Force
    New-Item -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "Logging" -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -PropertyType "DWORD" -Value 16384 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -PropertyType "DWORD" -Value 16384 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultOutboundAction" -PropertyType "DWORD" -Value 0 -Force
    # New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -PropertyType "DWORD" -Value 0 -Force
    # New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -PropertyType "DWORD" -Value 16384 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType "DWORD" -Value 1 -Force
}
