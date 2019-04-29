# Auto-Fix
gci

# Suppression
function Get-foo {
        # [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "",
        #                                                    Justification="This script has to run on PSv4 as well.")]
        param()
        Write-Host
}


# Formatting: Ctrl + K + F 
# powershell.codeFormatting.preset: https://github.com/PoshCode/PowerShellPracticeAndStyle/issues/81
if ($true)
{

}

# PSPossibleIncorrectUsageOfRedirectionOperator (added in 1.17.1)
if ($a > $b) {

}

# PSPossibleIncorrectUsageOAssignmentOperator (added in 1.17.1)
if ($a = $b) {

}

Invoke-Expression -Command '#format c'


# PSUseDeclaredVarsMoreThanAssignments: limited to scriptblock scope
$f = 4
# Get-Something $f


### New features in 1.18.0

# auto-fix added in 1.18.0
if ($null -eq $a) { }

## Formatting

# powershell.codeFormatting.pipelineIndentationStyle -> explain defaults
foo |
bar |
baz

# whitespaceInsideBrace
foo | ForEach-Object {bar}

# whitespaceAroundPipe
foo|bar

# useCorrectCasing
get-childitem

# Setting support: https://github.com/PowerShell/PSScriptAnalyzer#settings-support-in-scriptanalyzer
# -> enable setting: "powershell.scriptAnalysis.settingsPath": "PSScriptAnalyzerSettings.psd1",
