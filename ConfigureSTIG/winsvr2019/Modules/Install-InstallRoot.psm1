#Variables
[IO.FileInfo]$IRmsi = "$StagingPath\Support Files\InstallRoot.msi"

#Variables
###[IO.FileInfo]$IRmsi = "$StagingPath\Support Files\InstallRoot.msi"

#Function to force a exit, reboot
Function ExitWithReboot {
    Exit 3010
}

#Create StateObject to track reboots if required by an installer.
Function New-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $false)]
        [UInt32]$Install = 0,

        [Parameter(Mandatory = $false)]
        [UInt32]$TryCount = 0
    )

    [Object]$stateObject = $null

    $stateObject = New-Object -TypeName PSObject -Property @{Install = $Install; TryCount = $TryCount }

    Return $stateObject
}

#Read the state record, only used if required by a installer.
Function Read-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    [Object]$stateObject = $null

    If (Test-Path -Path $Path) {
        $stateObject = Get-Content $Path -Raw | ConvertFrom-Json
    }
    Else {
        $stateObject = New-StateObject
    }

    Return $stateObject
}

#Writes to the StateObject to keep track of progress.
Function Write-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $true)]
        [Object]$State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    ConvertTo-Json -InputObject $State | Out-File $Path -Force
}

#Check InstallRoot Version
Function Get-InstallRoot {

    Try {
        $Installed = (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*InstallRoot*" })
    }
    Catch {
        "Failed to check if InstallRoot is installed due to: $_"
        Invoke-Cleanup
        Exit -1
    }

    If ( $null -ne $Installed ) {
        [string]$major = $Installed.VersionMajor
        [string]$minor = $Installed.VersionMinor
        [string]$installedVersion = $major + "." + $minor

        Try {
            $winInstaller = New-Object -com WindowsInstaller.Installer
            $winInsDB = $winInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $winInstaller, @($IRmsi.FullName, 0))

            $query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
            $view = $winInsDB.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $winInsDB, ($query))

            $view.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $view, $Null)
            $record = $View.GetType().InvokeMember( "Fetch", "InvokeMethod", $Null, $view, $Null )
            $MSIversion = $record.GetType().InvokeMember( "StringData", "GetProperty", $Null, $record, 1 )

        }
        Catch {
            "Unable to get the MSI version, due to: $_"
        }

        If ($installedVersion -ne $MSIversion) {
            Install-InstallRoot
        }
        Else {
            "InstallRoot already installed at the current version, $InstalledVersion"
        }
    }
    Else {
        Install-InstallRoot
    }
}

#Function to install InstallRoot
Function Install-InstallRoot {

    [UInt32]$MaxRetry = 3
    [string]$StateFile = "$StagingPath\sate_installroot.txt"
    [PSObject]$StateObj = Read-StateObject -Path $StateFile

    If ($stateObj.Install -eq "0") {
        "Attempting to install InstallRoot attempt $($StateObj.TryCount) of $($MaxRetry)."

        Try {
            $InstallRootInstall = Start-Process -Wait "$IRmsi" -ArgumentList '/q' -PassThru
        }
        Catch {
            "Failed to install InstallRoot, due to: $_"
        }

        If (($InstallRootInstall.ExitCode -eq 0) ) {
            "Installation was successful."
            $StateObj.Install = 1
            Write-StateObject -State $StateObj -Path $StateFile
        }
        Elseif (($StateObj.TryCount) -ge $MaxRetry) {
            Write-Warning "Rebooted and attempted to install $($StateObj.TryCount) times. Max retry count is 3, exiting."
            Throw "Rebooted and tried to install $($StateObj.TryCount) times. Max retry count is 3, exiting."
            Invoke-Cleanup
            Exit -1
        }
        Else {
            "Will reboot and retry $($MaxRetry - ($StateObj.TryCount)) more times."
            $StateObj.TryCount += 1
            ExitWithReboot
        }
    }
}
