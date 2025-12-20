# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

The security of our compliance automation scripts is important. If you discover a security vulnerability, please follow these steps:

### 1. Contact

Send an email to: **bgauger@quantum-intl.com**

Please include:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### 2. Response Timeline

- **Initial Response**: Within 48 hours, we will acknowledge receipt of your vulnerability report
- **Status Update**: Within 7 days, we will provide a detailed response indicating the next steps
- **Resolution**: We aim to release patches or mitigations within 30 days for critical vulnerabilities

### 3. Disclosure Policy

- Please allow us reasonable time to fix the vulnerability before public disclosure
- We will credit you for the discovery (unless you prefer to remain anonymous)
- We will keep you informed of our progress toward resolution

## Security Considerations for Users

### Script Execution

These scripts make significant system configuration changes. Before running:

1. **Review the Code**: Always review scripts before execution to understand what changes will be made
2. **Test Environment**: Test in a non-production environment first
3. **Backups**: Create full system backups before applying STIG configurations
4. **Execution Policy**: Ensure your PowerShell execution policy is set appropriately
5. **Administrator Rights**: Scripts require administrative privileges - ensure proper authorization

### Best Practices

- **Never commit credentials** to version control
- **Use secure channels** when transferring scripts between systems
- **Verify script integrity** - consider implementing script signing
- **Audit logging** - enable logging to track configuration changes
- **Regular updates** - keep scripts updated with latest STIG versions
- **Principle of least privilege** - only run with necessary permissions

### Known Security Considerations

1. **Administrative Privileges**: Scripts require administrator access to modify system configurations
2. **System Changes**: Scripts make permanent changes to Windows registry, policies, and configurations
3. **Service Impact**: Some configurations may impact system services and applications
4. **Network Security**: TLS/SSL scripts affect network communication security settings

### Credential Handling

- Scripts should **never** store or log passwords or credentials
- Use **secure credential management** solutions (e.g., Azure Key Vault, CyberArk)
- Avoid passing credentials as command-line parameters
- Use **PowerShell SecureString** for sensitive data when necessary

### Compliance and Auditing

- These scripts implement DISA STIG requirements, but **verification is required**
- Use **STIG Viewer** or other compliance tools to validate configurations
- Maintain **audit logs** of when and what configurations were applied
- Regularly **review and update** to latest STIG versions

## Security Updates

Security updates will be released as needed and documented in:
- GitHub Security Advisories
- CHANGELOG.md
- Release notes

## Scope

This security policy applies to:
- All PowerShell scripts in this repository
- Configuration files and modules
- Documentation that impacts security

## Out of Scope

- Third-party dependencies and their vulnerabilities
- Security issues in Windows OS itself (report to Microsoft)
- Security issues in applications being configured (report to respective vendors)

## Additional Resources

- [DISA STIG Information](https://public.cyber.mil/stigs/)
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/security/overview)
- [Windows Security Baseline](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)

## Questions

For questions about this security policy, contact: bgauger@quantum-intl.com

---

**Note**: This project is provided "as is" without warranty. Users are responsible for testing and validating in their environment.
