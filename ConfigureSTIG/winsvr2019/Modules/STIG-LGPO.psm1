#Determine OS and set variable names for future use.
Function Get-OS {

    [Parameter(Mandatory = $true)]
    [string]$OSReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    [array]$OSRegValues = Get-ItemProperty -Path $OSReg
    [string]$OSNameTmp = $OSRegValues.ProductName
    [string]$OSTypeTmp = $OSRegValues.InstallationType

    #Set name to match folder structure
    If ($OSNameTmp -like "*2019*") {
        $script:OSName = "2019"
    }
    ElseIf ($OSNameTmp -like "*2022*") {
        $script:OSName = "2022"
    }

    If ($OSTypeTmp -like "*Nano*") {
        "Nano server is currently unsupported.  Exiting SSM."
        Invoke-Cleanup
        Exit -1
    }
}

#A function to copy over the ADMX, and ADML file to apply further configuration settings.
Function Copy-ADML {

    If ($script:OSName -eq "2019") {
        Try {
            Copy-Item -Path "$StagingPath\2019\Support Files\MSS-Legacy.admx" -Destination "$Env:WinDir\PolicyDefinitions\MSS-Legacy.admx" | Out-Null
            Copy-Item -Path "$StagingPath\2019\Support Files\MSS-Legacy.adml" -Destination "$Env:WinDir\PolicyDefinitions\en-US\MSS-Legacy.adml" | Out-Null
            "Copied MSS-Legacy admx/adml files to be used for their STIG settings."
        }
        Catch {
            "Failed to copy MSS-Legacy policies, due to: $_"
            Invoke-Cleanup
            Exit -1
        }
    }

    Try {
        Copy-Item -Path "$StagingPath\2019\Support Files\SecGuide.admx" -Destination "$Env:WinDir\PolicyDefinitions\SecGuide.admx" | Out-Null
        Copy-Item -Path "$StagingPath\2019\Support Files\SecGuide.adml" -Destination "$Env:WinDir\PolicyDefinitions\en-US\SecGuide.adml" | Out-Null
        "Copied SecGuide admx/adml files to be used for their STIG settings."
    }
    Catch {
        "Failed to copy SecGuide policies, due to: $_"
        Invoke-Cleanup
        Exit -1
    }

    If ($script:OSName -eq "2012R2") {
        Update-sceregvl
    }
}

#Function to apply group policies via LGPO.exe
Function Invoke-LGPO {

    [string]$GPBackupPath = "$StagingPath\$script:OSName\OS"
    [string]$GPBackup = Get-ChildItem -Directory -Path $GPBackupPath
    $GPBackup = "$GPBackupPath\$GPBackup"

    If ($GPBackup -eq $null) {
        "No policy located."
        Invoke-Cleanup
        Exit -1
    }

    Try {
        &"$StagingPath\Support Files\LGPO.exe" /q /g $GPBackup
    }
    Catch {
        "Failed to apply setting, due to: $_"
        Invoke-Cleanup
        Exit -1
    }

    Try {
        &Gpupdate /force
    }
    Catch {
        "Failed to update group policy, due to: $_"
        Invoke-Cleanup
        Exit -1
    }
}

#Remove and Refresh Local Policies
Function Set-LGPO {
    $LgpoTmpl = "$StagingPath/2019/OS/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit"
    # Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    # Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    secedit /configure /cfg "$LgpoTmpl/GptTmpl.inf" /db "$LgpoTmpl/GptTmpl.sdb" /verbose | Out-Null
}


# WN19-AU-000100/ V-205625  WN19-AU-000110/ V-205626  WN19-AU-000120/ V-205627
Function Set-Auditing {
    $auditTmpl = "$StagingPath/2019/OS/DomainSysvol/GPO/Machine/microsoft/windows nt/Audit"
    #Clear Audit Policy
    auditpol /clear /y
    #Enforce the Audit Policy Baseline
    auditpol /restore /file:$auditTmpl/audit.csv
}