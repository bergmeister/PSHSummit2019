@{
    IncludeDefaultRules = $true
	ExcludeRules = @(
        'PSUseDeclaredVarsMoreThanAssignments'
    )
    Rules = @{
        PSUseCompatibleCmdlets = @{
            compatibility = @('core-6.1.0-windows', 'desktop-4.0-windows')
        }
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @(
                '3.0',
                '5.1',
                '6.2'
            )
        }
        PSUseCompatibleCommands = @{
            Enable = $true
            TargetProfiles = @(
                'win-8_x64_10.0.14393.0_6.1.3_x64_4.0.30319.42000_core', # PS 6.1 on WinServer-2019
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', # PS 5.1 on WinServer-2019
                'win-8_x64_6.2.9200.0_3.0_x64_4.0.30319.42000_framework' # PS 3 on WinServer-2012
            )
        }
        PSUseCompatibleTypes = @{
            Enable = $true
            TargetProfiles = @(
                'ubuntu_x64_18.04_6.1.3_x64_4.0.30319.42000_core',
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
            )
            # You can specify types to not check like this, which will also ignore methods and members on it:
            IgnoreTypes = @(
                'System.IO.Compression.ZipFile'
            )
        }
    }
}