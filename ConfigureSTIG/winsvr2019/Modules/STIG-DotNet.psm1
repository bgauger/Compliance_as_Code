Function Set-DotNetSTIG {
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value 1 -Force
}
