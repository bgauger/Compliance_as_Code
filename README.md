# Compliance as Code

A collection of PowerShell scripts for automated Security Technical Implementation Guide (STIG) compliance configuration and evaluation for Windows Server and IIS environments.

## Overview

This repository provides automated compliance-as-code solutions to configure Windows systems according to DISA STIG requirements. The scripts help system administrators apply and validate security configurations efficiently and consistently.

## Repository Structure

```
Compliance_as_Code/
├── ConfigureSTIG/          # Scripts to configure systems for STIG compliance
│   ├── IIS10/             # IIS 10.0 STIG configuration scripts
│   ├── TLS/               # TLS/SSL security configuration
│   └── winsvr2019/        # Windows Server 2019 STIG configuration
│       ├── Modules/       # PowerShell modules for various applications
│       └── Support Files/ # Additional support files and resources
└── EvalSTIG/              # STIG evaluation and validation
    └── AnswerFilesIL4/    # Answer files for STIG Viewer assessments
```

## Features

### Configuration Scripts

- **Windows Server 2019 STIG** (`ConfigureSTIG/winsvr2019/Win2019-STIG.ps1`)
  - Comprehensive STIG configuration for Windows Server 2019
  - Modular design with support for multiple application STIGs
  - Includes STIGs for: Adobe Reader, Chrome, Defender, DotNet, Edge, Firefox, Firewall, IE11, IIS, Office, and more

- **IIS 10.0 STIG** 
  - Server configuration: `ConfigureSTIG/IIS10/IIs10-Server-STIG_v2.5.ps1`
  - Site configuration: `ConfigureSTIG/IIS10/IIs10-Site-STIG_v2.5.ps1`
  - Based on IIS 10.0 STIG Version 2, Release 5 (27 Jan 2022)

- **TLS/SSL Security** (`ConfigureSTIG/TLS/set_tls.ps1`)
  - Disables weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
  - Enables strong protocols (TLS 1.2, TLS 1.3)
  - Configures secure cipher suites and hashing algorithms

## Prerequisites

- **Operating System**: Windows Server 2019 or compatible Windows version
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Administrator privileges required
- **IIS**: Internet Information Services (for IIS STIG scripts)

## Usage

### Basic Usage

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/bgauger/Compliance_as_Code.git
   cd Compliance_as_Code
   ```

2. **Run with Administrator privileges**:
   ```powershell
   # Right-click PowerShell and select "Run as Administrator"
   ```

3. **Execute STIG configuration scripts**:

   ```powershell
   # Windows Server 2019 STIG
   .\ConfigureSTIG\winsvr2019\Win2019-STIG.ps1
   
   # With specific category
   .\ConfigureSTIG\winsvr2019\Win2019-STIG.ps1 -Cat "Server2019"
   
   # IIS Server STIG
   .\ConfigureSTIG\IIS10\IIs10-Server-STIG_v2.5.ps1
   
   # IIS Site STIG
   .\ConfigureSTIG\IIS10\IIs10-Site-STIG_v2.5.ps1
   
   # TLS/SSL Configuration
   .\ConfigureSTIG\TLS\set_tls.ps1
   ```

### Windows Server 2019 Script Parameters

```powershell
.\ConfigureSTIG\winsvr2019\Win2019-STIG.ps1 `
    -Cat "Server2019" `
    -StagingPath "C:\StigPrep" `
    -EnableCleanup "Yes"
```

**Parameters:**
- `-Cat`: STIG category to apply (Server2019, IISSvr, DevWS, TestWS, NetOpsWS, SQL)
- `-StagingPath`: Directory for temporary files (default: C:\StigPrep)
- `-EnableCleanup`: Clean up temporary files after execution (Yes/No, default: Yes)

## Important Notes

⚠️ **WARNING**: These scripts make significant system configuration changes. 

- **Test in a non-production environment first**
- **Create system backups** before running any scripts
- **Review scripts** to understand the changes being made
- **Verify compliance requirements** match your organization's needs
- Some changes may require a **system restart** to take effect

## STIG Versions

Scripts are based on the following STIG versions:
- Windows Server 2019: Various application STIGs
- IIS 10.0 Server/Site: Version 2, Release 5 (27 Jan 2022)

Always verify you're using the appropriate STIG version for your compliance requirements.

## Evaluation and Validation

The `EvalSTIG/AnswerFilesIL4/` directory contains answer files for use with DISA STIG Viewer to evaluate and document compliance status.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Original Author**: Ben Gauger, Quantum Research International  
**Email**: bgauger@quantum-intl.com

## References

- [DISA STIGs](https://public.cyber.mil/stigs/)
- [STIG Viewer](https://public.cyber.mil/stigs/srg-stig-tools/)
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)

## Disclaimer

This software is provided "as is" without warranty of any kind. Users are responsible for testing and validating these scripts in their environment and ensuring they meet their specific compliance requirements.
