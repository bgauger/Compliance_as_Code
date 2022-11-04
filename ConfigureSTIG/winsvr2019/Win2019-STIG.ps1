######SCRIPT FOR WINDOWS SERVER 2019 STIG#####

<#
.SYNOPSIS
    Applies changes to Windows Server configuration to be STIG compliant.

.DESCRIPTION
    This powershell script applies several configuration changes to Windows Server configuration to meet STIG guidance. It will apply various STIG settings using either local group policy, registry changes, or installing the certificate software.
    Script is applicable to "Microsoft IIS 10.0 Site Security Technical Implementation Guide"
    Version 2, Release: 5 Benchmark Date: 27 Jan 2022

.PARAMETER Level
    Used to set what catagory of STIG you want to apply.  Examples OS, .Net, IE, Firewall, All

.PARAMETER StagingPath
    The location used to run files out of as needed.
    
.EXAMPLE
    .\Win2019-STIG.ps1

.NOTES
    Original Author:      Ben Gauger, Quantum Research International - bgauger@quantum-intl.com
    Additional Authors:
    Revision History:  
    V1 - 3/24/2022     - Initial version started
    V2 - 10/25/2022    - Format Changes
#>

#Set input parameters to be used with SSM doc
Param(
    [Parameter (Position = 1)]
    [ValidateSet("Server2019", "IISSvr", "DevWS", "TestWS", "NetOpsWS", "SQL")]
    [string]$Cat = "Server2019", #Default level to run

    [Parameter (Position = 2)]
    [string]$StagingPath = "C:\StigPrep",      #To allow pass through of custom path for BOM.

    [Parameter (Position = 3)]
    [ValidateSet("Yes", "No")]
    [string]$EnableCleanup = "Yes"  #While normally yes, allowing to disable to assist with troubleshooting.
)

Function Get-Modules {
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Adobe.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Chrome.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Defender.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-DotNet.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Edge.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Firefox.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Firewall.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-IE11.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Office2016.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Office2019.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Excel-16.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Office-Base-16.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-PowerPoint-16.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Word-16.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\Install-InstallRoot.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-Server2019.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-IIS-Server.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-IIS-Site.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\Mitigations.psm1")
    Import-Module (Join-Path -Path $PsScriptRoot -ChildPath "Modules\STIG-LGPO.psm1")
}

#Apply STIGs
Function Set-STIG {

    If ($Cat -eq "Server2019") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
    }
    ElseIf ($Cat -eq "IISSvr") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
        Set-IISServerSTIG
        Set-IISSiteSTIG
    }
    ElseIf ($Cat -eq "DevWS") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
        Set-ChromeSTIG
        Set-FirefoxSTIG
        Set-EdgeSTIG
        Set-Office2019STIG
        Set-AdobeSTIG
        Set-IISServerSTIG
        Set-IISSiteSTIG
    }
    ElseIf ($Cat -eq "TestWS") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
        Set-ChromeSTIG
        Set-FirefoxSTIG
        Set-EdgeSTIG
        Set-Office2016STIG
        Set-AdobeSTIG
    }
    ElseIf ($Cat -eq "NetOpsWS") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
        Set-ChromeSTIG
        Set-FirefoxSTIG
    }
    ElseIf ($Cat -eq "SQL") {
        Set-STIGOS
        Set-DotNetSTIG
        Remove-IE11
    }
}

#Cleanup StigPrep
Function Invoke-Cleanup {

    If ($EnableCleanup -like "Yes"){
        Try {
            Push-Location C:\
            Remove-Item -Path "$StagingPath" -Recurse
            "$StagingPath has been removed."
            Exit 0
        }
        Catch {
            "Failed to clean up the staging area, due to: $_"
            Exit -1
        }
    } ElseIf ($EnableCleanup -like "No"){
        "Cleanup was disabled exiting"
    }
}

#Validate/Set Cat
If ($Cat -like "Server2019") {
    $Cat = "Server2019"
}
ElseIf ($Cat -like "IISSvr") {
    $Cat = "IISSvr"
}
ElseIf ($Cat -like "DevWS") {
    $Cat = "DevWS"
}
ElseIf ($Cat -like "TestWS") {
    $Cat = "TestWS"
}
ElseIf ($Cat -like "NetOpsWS") {
    $Cat = "NetOpsWS"
}
ElseIf ($Cat -like "SQL") {
    $Cat = "SQL"
}
Else {
    "$Cat is not a valid STIG catagory, exiting."
    Exit -1
}

Get-Modules
Get-OS
Copy-ADML
Set-STIG
Invoke-LGPO
Invoke-Cleanup