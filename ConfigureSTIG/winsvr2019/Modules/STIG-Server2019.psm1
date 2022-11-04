<#
    Windows STIG settings
#>

<#Listing Windows Server STIG Items that are included in the AWS STIG AMI/ this script applying items to local group policy.

WN19-AC-000020/ V-205629  WN19-AC-000030/ V-205630  WN19-AU-000190/ V-205634
WN19-AU-000200/ V-205635  WN19-UR-000170/ V-205643  WN19-AC-000080/ V-205652
WN19-AC-000090/ V-205653  WN19-AC-000060/ V-205656	WN19-AC-000040/ V-205660
WN19-AC-000070/ V-205662  WN19-MS-000070/ V-205671  WN19-MS-000080/ V-205672
WN19-MS-000090/ V-205673  WN19-MS-000100/ V-205674  WN19-MS-000110/ V-205675
WN19-UR-000030/ V-205676  WN19-SO-000010/ V-205709  WN19-00-000230/ V-205721
WN19-AU-000150/ V-205729  WN19-AU-000160/ V-205730  WN19-UR-000040/ V-205751
WN19-UR-000050/ V-205752  WN19-UR-000070/ V-205754  WN19-UR-000090/ V-205756
WN19-UR-000100/ V-205757  WN19-UR-000110/ V-205758  WN19-UR-000120/ V-205759
WN19-UR-000130/ V-205760  WN19-UR-000140/ V-205761  WN19-UR-000150/ V-205762
WN19-UR-000180/ V-205764  WN19-UR-000190/ V-205765  WN19-UR-000200/ V-205766
WN19-UR-000210/ V-205767  WN19-UR-000220/ V-205768  WN19-AU-000090/ V-205769
WN19-AU-000140/ V-205770  WN19-AU-000260/ V-205771  WN19-AU-000270/ V-205772
WN19-AU-000280/ V-205773  WN19-AU-000290/ V-205774  WN19-AU-000300/ V-205775
WN19-AU-000310/ V-205776  WN19-AU-000320/ V-205777  WN19-AU-000330/ V-205778
WN19-AU-000340/ V-205779  WN19-AU-000350/ V-205780  WN19-AU-000360/ V-205781
WN19-AU-000370/ V-205782  WN19-AU-000380/ V-205783  WN19-AU-000390/ V-205784
WN19-AC-000010/ V-205795  WN19-AU-000070/ V-205832  WN19-AU-000080/ V-205833
WN19-AU-000170/ V-205834  WN19-AU-000210/ V-205835  WN19-AU-000220/ V-205836
WN19-AU-000230/ V-205837  WN19-AU-000180/ V-205838  WN19-AU-000130/ V-205839
WN19-AU-000240/ V-205840  WN19-AU-000250/ V-205841  


#>


<#Listing Windows Server STIG Items not included in script as they are manual checks or vary greatly for implementations, or will be re-evaluated in next release of script.
WN19-00-000020/ V-205657  WN19-00-000210/ V-205658  WN19-00-000050/ V-205661
WN19-00-000130/ V-205663  WN19-00-000180/ V-205664  WN19-00-000270/ V-205677
WN19-00-000070/ V-205699  WN19-00-000200/ V-205700  WN19-00-000190/ V-205707
WN19-00-000310/ V-205710  WN19-00-000250/ V-205727  WN19-00-000290/ V-205728  
WN19-MS-000010/ V-205746  WN19-MS-000130/ V-205748  WN19-UR-000010/ V-205749  
WN19-UR-000020/ V-205750  WN19-UR-000060/ V-205753  WN19-UR-000080/ V-205755  
WN19-UR-000160/ V-205763  WN19-AU-000010/ V-205799  WN19-00-000260/ V-205829
WN19-AU-000020/ V-205843  WN19-00-000010/ V-205844  WN19-00-000030/ V-205845
WN19-00-000040/ V-205846  WN19-00-000060/ V-205847  WN19-00-000090/ V-205848
WN19-00-000100/ V-205849  WN19-00-000110/ V-205850  WN19-00-000120/ V-205851
WN19-00-000240/ V-205852  WN19-00-000450/ V-205855  WN19-00-000460/ V-205856
WN19-00-000470/ V-205857  WN19-MS-000140/ V-205907  WN19-SO-000030/ V-205909
WN19-SO-000040/ V-205910  WN19-00-000280/ V-214936

#>

<#Listing Windows Server STIG Items that need to be applied via Domain GPO.
WN19-SO-000130/ V-205631  WN19-SO-000140/ V-205632  WN19-00-000440/ V-205800
WN19-00-000220/ V-205803  WN19-00-000080/ V-205807  


#>

<#Listing Windows Server STIG Items that are NA.
WN19-DC-000230/ V-205628  WN19-DC-000280/ V-205645  WN19-DC-000290/ V-205646
WN19-DC-000300/ V-205647  WN19-DC-000340/ V-205665  WN19-DC-000360/ V-205666
WN19-DC-000370/ V-205667  WN19-DC-000380/ V-205668  WN19-DC-000390/ V-205669
WN19-DC-000400/ V-205670  WN19-DC-000130/ V-205695  WN19-DC-000310/ V-205701
WN19-DC-000020/ V-205702  WN19-DC-000030/ V-205703  WN19-DC-000040/ V-205704
WN19-DC-000050/ V-205705  WN19-DC-000060/ V-205706  WN19-DC-000120/ V-205723
WN19-DC-000160/ V-205726  WN19-DC-000410/ V-205732  WN19-DC-000010/ V-205738  
WN19-DC-000070/ V-205739  WN19-DC-000080/ V-205740  WN19-DC-000090/ V-205741  
WN19-DC-000100/ V-205742  WN19-DC-000110/ V-205743  WN19-DC-000350/ V-205744  
WN19-DC-000420/ V-205745  WN19-DC-000170/ V-205785  WN19-DC-000180/ V-205786  
WN19-DC-000190/ V-205787  WN19-DC-000200/ V-205788  WN19-DC-000210/ V-205789  
WN19-DC-000220/ V-205790  WN19-DC-000240/ V-205791  WN19-DC-000250/ V-205792  
WN19-DC-000260/ V-205793  WN19-DC-000270/ V-205794  WN19-DC-000140/ V-205818  
WN19-DC-000320/ V-205820  WN19-DC-000150/ V-205875  WN19-DC-000330/ V-205876
WN19-DC-000430/ V-205877  
#>



# WN19-AU-000030/ V-205640, 000040/ V-205641, 000050/ V-205642
Function Set-V205640 {
    $appfileloc = "C:\Windows\System32\winevt\Logs"
    takeown /f $appfileloc /A
    icacls $secfileloc /reset /
}


<#
Checks to see if InstallRoot is installed, required for various DoD certs.  STIG Vul V-205648.
If InstallRoot isn't installed will run the Install-InstallRoot function to install it.  Then cleans it after.
#>

# WN19-PK-000010/ V-205648, WN19-PK-000020/ V-205649, WN19-PK-000030/ V-205650
Function Set-V205648 {

    Get-InstallRoot

    Try {
        &"$Env:Programfiles\DoD-PKE\InstallRoot\InstallRoot.exe" | Out-Null
        "Ran InstallRoot and Certificates Updated"
    }
    Catch {
        "Failed to run InstallRoot, due to: $_"
        Invoke-Cleanup
        Exit -1
    }

    Try {
        &"$StagingPath\Support Files\FBCA_crosscert_remover.exe" /s
    }
    Catch {
        "Failed to run the FBCA Crosscert Remover, due to: $_"
        Invoke-Cleanup
        Exit -1
    }
}

#Remove fax service per Vul ID V-205678
Function Set-V205678 {

    If (Get-WindowsFeature -Name Fax | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Fax
            "The fax service has been uninstalled from the system, per V-205678"
        }
        Catch {
            "Failed to uninstall the fax service due to: $_. Not compliant with V-205678."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The fax service is uninstalled from the system, per V-205678."
    }
}

#Remove Peer Networking Identity Manager (Peer Name Resolution Protocol) from server, per V-205679
Function Set-V205679 {

    If (Get-WindowsFeature -Name PNRP | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name PNRP
            "The Peer Networking Identity Manager service has been removed, per V-205679."
        }
        Catch {
            "Failed to uninstall Peer Networking Identity Manager service, due to: $_. Not compliant with V-205679."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The Peer Networking Identity Manager service has been removed, per V-205679."
    }
}

#Remove simple TCPIP service from server, per V-205680
Function Set-V205680 {

    If (Get-WindowsFeature -Name PNRP | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Simple-TCPIP
            "The Simple TCPIP service has been removed, per V-205680."
        }
        Catch {
            "Failed to uninstall Simple TCPIP service, due to: $_. Not compliant with V-205680."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The Simple TCPIP service has been removed, per V-205680."
    }
}

#Uninstall TFTP-Client per V-205681
Function Set-V205681 {

    Try {
        Uninstall-WindowsFeature -Name TFTP-Client
    }
    Catch {
        "Failed to uninstall TFTP-Client, due to: $_. Not compliant with V-205681."
        Invoke-Cleanup
        Exit -1
    }
}

#Remove SMB 1 per Vul ID V-205682, will require a restart to take full affect and check.
Function Set-V205682 {

    If (Get-WindowsFeature -Name FS-SMB1 | Where-Object InstallState -EQ Installed) {
        Try {
            Uninstall-WindowsFeature -Name FS-SMB1
            "SMB1 uninstalled from system, per V-205682."
        }
        Catch {
            "Failed to uninstall SMB1 due to: $_. Not complaint with V-205682."
            Invoke-Cleanup
            Exit -1
        }
    }
}

#Uninstall Powershell 2.0 per V-205685
Function Set-V205685 {
    Try {
        Uninstall-WindowsFeature -Name PowerShell-v2
    }
    Catch {
        "Failed to uninstall PowerShell V2, due to: $_. Not compliant with V-205685."
        Invoke-Cleanup
        Exit -1
    }
}

#Remove MS FTP service per V-205853/V-205854/V-205697
Function Set-V205697 {

    If (Get-WindowsFeature -Name Web-FTP-Server | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Web-FTP-Server
            "The FTP service has been uninstalled, per V-205853, V-205854, V-205697."
        }
        Catch {
            "Failed to uninstall the FTP service, due to: $_. Not compliant with V-205853, V-205854, V-205697."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The FTP service is uninstalled from the system, per V-205853, V-205854, V-205697."
    }
}

#Remove simple telnet client from server, per V-205698
Function Set-V205698 {

    If (Get-WindowsFeature -Name Telnet-Client | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Telnet-Client
            "The Telnet service has been removed, per V-205698."
        }
        Catch {
            "Failed to uninstall the Telnet service, due to: $_. Not compliant with V-205698."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The Telnet service has been removed, per V-205698."
    }
}

#Remove PFX certs from systems.
Function Set-V205852 {
    Get-ChildItem * -Include *.pfx -Recurse | Remove-Item
}

#Remove IE11 if it is installed.
Function Remove-IE11 {
    If (Get-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online | Where-Object State -eq Enabled) {
        Try {
            Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online
            "Removal of IE11 due to EOL June 2022."
            ExitWithReboot
        }
        Catch {
            "Failed to uninstall IE11, due to: $_. Not compliant with current requirements."
            Invoke-Cleanup
            Exit -1
        }
    }
    Else {
        "The IE11 service is uninstalled from the system."
    }
}

#Event Viewer must be protected from unauthorized modification and deletion per V-205731.
# Function Set-V205731 {
#     Try {
#     $eventloc = "%SystemRoot%\System32\Eventvwr.exe"
#     takeown /f $eventloc /A /R
#     icacls $eventloc /grant TrustedInstaller:RX /t /c
#     icacls $eventloc /grant system:RX /t /c
#     icacls $eventloc /grant users:RX /t /c
#     icacls $eventloc /grant ALL APPLICATION PACKAGES:RX /t /c
#     icacls $eventloc /grant ALL RESTRICTED APPLICATION PACKAGES:RX /t /c
#     }
#     Catch {
#         "Failed to set Event Viewer from protection of unauthorized modification and deletion, due to: $_. Not compliant with V-205731."
#         Invoke-Cleanup
#         Exit -1
#     }
# }

#ALL the OS STIGs
Function Set-STIGOS {
    
    Set-LGPO
    Set-Auditing
    Set-V205640 
    Set-V205648
    Set-V205678 
    Set-V205679
    Set-V205680 
    Set-V205681
    Set-V205682 
    Set-V205685
    Set-V205697 
    Set-V205698
    Set-V205852
}