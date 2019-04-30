# Auto-Fix
gci

# Formatting: Ctrl + K + F 
if ($true)
{

}

# PSPossibleIncorrectUsageOfRedirectionOperator
if ($a > $b) {

}

# PSPossibleIncorrectUsageOfAssignmentOperator
if ($a = $b) {

}

# PSUseCompatibleCmdlets
Compress-Archive

# PSUseCompatibleSyntax (show fix as well)
[System.Collections.Generic.Dictionary[string, string]]::new()

# PSUseCompatibleCommands
Get-FileHash -LiteralPath $literalPath
Import-Module -FullyQualifiedName @{ ModuleName = ArchiveHelper; ModuleVersion = '1.1' }
Split-Path -LeafBase $path
Compress-Archive
Out-File -LiteralPath $literalPath -NoNewline

# PSUseCompatibleTypes
[System.Management.Automation.SemanticVersion]"1.18.0-rc1"
[System.Windows.Forms.Form]::ActiveForm # WinForms not loaded by default and therefore not part of the JSON files

###################################################################

# PSAvoidUsingCmdletAlias for implicit 'Get-' alias (if applicable on the given platform)
service
curl

###################################################################

Show-Ast { if($a -eq "$b.sth()"){ } }