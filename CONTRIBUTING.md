# Contributing to Compliance as Code

Thank you for your interest in contributing to the Compliance as Code project! This document provides guidelines for contributing to this repository.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check the [Issues](https://github.com/bgauger/Compliance_as_Code/issues) to see if it has already been reported
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - System information (Windows version, PowerShell version)
   - STIG version being targeted

### Submitting Changes

1. **Fork the repository** and create a new branch for your changes
   ```powershell
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding guidelines below

3. **Test your changes** thoroughly in a test environment

4. **Commit your changes** with clear, descriptive commit messages
   ```powershell
   git commit -m "Add feature: description of what you added"
   ```

5. **Push to your fork** and submit a pull request
   ```powershell
   git push origin feature/your-feature-name
   ```

## Coding Guidelines

### PowerShell Style

- Use **PascalCase** for function names: `Get-StigConfiguration`
- Use **camelCase** for variable names: `$stagingPath`
- Use **verb-noun** naming convention for functions
- Include **comment-based help** for all functions and scripts
- Use **4 spaces** for indentation (not tabs)
- Keep lines under **120 characters** when possible

### Script Structure

1. **Header comment block** with:
   - Synopsis
   - Description
   - Parameters
   - Examples
   - Notes (author, version history)

2. **Parameters section** with validation

3. **Functions** before main script logic

4. **Main script logic** with proper error handling

### Example Format

```powershell
<#
.SYNOPSIS
    Brief description of the script

.DESCRIPTION
    Detailed description of what the script does

.PARAMETER ParameterName
    Description of the parameter

.EXAMPLE
    .\Script-Name.ps1 -ParameterName "Value"
    
.NOTES
    Author: Your Name
    Date: YYYY-MM-DD
    Version: 1.0
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ParameterName
)

function Verb-Noun {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Parameter
    )
    
    # Function logic here
}

# Main script logic
try {
    # Your code here
}
catch {
    Write-Error "Error message: $_"
    exit 1
}
```

## Testing

- **Test in a non-production environment** before submitting
- Verify scripts run without errors on target systems
- Check that STIG requirements are properly implemented
- Validate that scripts are idempotent (can be run multiple times safely)
- Test both success and failure scenarios

## Documentation

- Update **README.md** if adding new features or scripts
- Document all **parameters** and their acceptable values
- Provide **usage examples** for new scripts
- Update **CHANGELOG.md** with your changes
- Include **inline comments** for complex logic

## STIG Compliance

- Reference the **specific STIG version** being implemented
- Include **STIG IDs** (e.g., V-93345) in comments where applicable
- Verify against the **official STIG documentation**
- Document any **deviations** or **non-applicable** items

## Security Considerations

- **Never commit credentials** or sensitive information
- Ensure scripts follow **principle of least privilege**
- Validate all **user inputs**
- Use **secure coding practices**
- Consider **audit logging** for configuration changes

## Pull Request Process

1. Ensure your code follows the coding guidelines
2. Update documentation as needed
3. Add a clear description of changes in the PR
4. Reference any related issues
5. Wait for review and address any feedback
6. Once approved, your PR will be merged

## Code of Conduct

Please note that this project follows a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Questions?

If you have questions about contributing, please:
- Open an issue for discussion
- Contact the maintainer: bgauger@quantum-intl.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping improve Compliance as Code!
