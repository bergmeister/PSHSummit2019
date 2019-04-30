#[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomPSScriptAnalyzerRules\WarningAboutDoSomething', '')]
Param()

# Custom rule
Invoke-Something

Invoke-Expression

gci # PSAvoidUsingCmdletAliases is suppressed -> no warning