function WarningAboutDoSomething {
    <#
    .DESCRIPTION
        Custom rule text when you call Invoke-Something.
    #>

    param (
        [System.Management.Automation.Language.CommandAst]$ast
    )

    if ($ast.GetCommandName() -eq 'Invoke-Something') {
        [int]$startLineNumber =  $ast.Extent.StartLineNumber
        [int]$endLineNumber = $ast.Extent.EndLineNumber
        [int]$startColumnNumber = $ast.Extent.StartColumnNumber
        [int]$endColumnNumber = $ast.Extent.EndColumnNumber
        [string]$correction = 'Invoke-SomethingElse'
        $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,'description'
        $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
        $suggestedCorrections.add($correctionExtent) | Out-Null

        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
            RuleName               = $myinvocation.InvocationName
            Message                = 'Message about usage of Invoke-Something'
            Extent                 = $ast.Extent
            "Severity"             = "Warning"
            "SuggestedCorrections" = $suggestedCorrections
        }
    }
}
