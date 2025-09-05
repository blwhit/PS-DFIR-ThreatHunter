# DFIRHunter Manifest
@{
    # Script module file this manifest is for
    RootModule        = 'DFIR-Hunter.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # Unique identifier for this module (generate with [guid]::NewGuid())
    GUID              = '48e59dc3-154d-4db0-a9c7-2c57dde9103b'

    # Author info
    Author            = 'Blake White'
    CompanyName       = ''

    # Description of the module
    Description       = 'PowerShell Digital Forensics and Incident Response (DFIR) momdule for Hunting.'

    # Minimum PowerShell version
    PowerShellVersion = '5.1'

    # Exported members
    FunctionsToExport = @('Hunt-Logs')
    CmdletsToExport   = @()
    # Global Config Vars
    VariablesToExport = @()
    # Set and export aliases for functions
    AliasesToExport   = @()

    # External dependencies
    RequiredModules   = @()
    RequiredAssemblies = @('System.IO.Compression.FileSystem.dll')

    # Optional: nested modules
    NestedModules     = @()

    # Private module data (metadata only)
    PrivateData = @{
        PSData = @{
            Tags         = @('Digital Forensics','Incident Response','DFIR','Forensics')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/blwhit/PS-DFIR-Hunter'
            ReleaseNotes = 'Initial release, 2025.'
        }
    }
}
