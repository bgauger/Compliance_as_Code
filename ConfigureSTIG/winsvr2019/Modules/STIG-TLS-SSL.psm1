Function Set-TlsSsl {
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", $true)
    $newkey.CreateSubKey('SSL 2.0')
    $newkey.CreateSubKey('SSL 3.0')
    $newkey.CreateSubKey('TLS 1.1')
    $newkey.CreateSubKey('TLS 1.2')
    $newkey.CreateSubKey('TLS 1.3')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()
    $newkey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3", $true)
    $newkey.CreateSubKey('Client')
    $newkey.CreateSubKey('Server')
    $newkey.Close()

    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name DisabledByDefault -PropertyType DWORD -Value 0 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name DisabledByDefault -PropertyType DWORD -Value 0 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name DisabledByDefault -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name Enabled -PropertyType DWORD -Value 1 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -PropertyType DWORD -Value 0 -ea SilentlyContinue
}


