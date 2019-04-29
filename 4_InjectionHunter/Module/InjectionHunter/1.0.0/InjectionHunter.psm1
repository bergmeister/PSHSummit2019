######################################################################
##
## Rules
##
######################################################################

<#
.DESCRIPTION
    Finds instances of Invoke-Expression, which can be used to invoke arbitrary
    code if supplied with untrusted input.
#>
function Measure-InvokeExpression
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.CommandAst]
        if($targetAst)
        {       
            if($targetAst.CommandElements[0].Extent.Text -in ("Invoke-Expression", "iex"))
            {                      
                return $true;
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible script injection risk via the Invoke-Expression cmdlet. Untrusted input can cause " +
                         "arbitrary PowerShell expressions to be run. Variables may be used directly for dynamic parameter arguments, " +
                         "splatting can be used for dynamic parameter names, and the invocation operator can be used for dynamic " +
                         "command names. If content escaping is truly needed, PowerShell has several valid quote characters, so  " +
                         "[System.Management.Automation.Language.CodeGeneration]::Escape* should be used."
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.InvokeExpression"
            "Severity" = "Warning" }
    }
}


function Measure-AddType
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.CommandAst]
        if($targetAst)
        {       
            if($targetAst.CommandElements[0].Extent.Text -eq "Add-Type")
            {
                $addTypeParameters = [System.Management.Automation.Language.StaticParameterBinder]::BindCommand($targetAst)
                $typeDefinitionParameter = $addTypeParameters.BoundParameters.TypeDefinition

                ## If it's not a constant value, check if it's a variable with a constant value
                if(-not $typeDefinitionParameter.ConstantValue)
                {
                    if($addTypeParameters.BoundParameters.TypeDefinition.Value -is [System.Management.Automation.Language.VariableExpressionAst])
                    {
                        $variableName = $addTypeParameters.BoundParameters.TypeDefinition.Value.VariablePath.UserPath
                        $constantAssignmentForVariable = $ScriptBlockAst.FindAll( {
                            param(
                                [System.Management.Automation.Language.Ast] $Ast
                            )

                            $assignmentAst = $Ast -as [System.Management.Automation.Language.AssignmentStatementAst]
                            if($assignmentAst -and 
                               ($assignmentAst.Left.VariablePath.UserPath -eq $variableName) -and
                               ($assignmentAst.Right.Expression -is [System.Management.Automation.Language.ConstantExpressionAst]))
                            {
                                return $true
                            }
                        }, $true)

                        if($constantAssignmentForVariable)
                        {
                            return $false
                        }
                        else
                        {
                            return $true
                        }
                    }
                    
                    return $true
                }                
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible code injection risk via the Add-Type cmdlet. Untrusted input can cause " +
                         "arbitrary Win32 code to be run."
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.AddType"
            "Severity" = "Warning" }
    }
}


<#
.DESCRIPTION
    Finds instances of dangerous methods, which can be used to invoke arbitrary
    code if supplied with untrusted input.
#>
function Measure-DangerousMethod
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.InvokeMemberExpressionAst]
        if($targetAst)
        {
            if($targetAst.Member.Extent.Text -in ("InvokeScript", "CreateNestedPipeline", "AddScript", "NewScriptBlock", "ExpandString"))
            {
                return $true
            }

            if(($targetAst.Member.Extent.Text -eq "Create") -and
               ($targetAst.Expression.Extent.Text -match "ScriptBlock"))
            {
                return $true
            }           
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible script injection risk via the a dangerous method. Untrusted input can cause " +
                         "arbitrary PowerShell expressions to be run. The PowerShell.AddCommand().AddParameter() APIs " +
                         "should be used instead."
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.$($foundNode.Member.Extent.Text)"
            "Severity" = "Warning" }
    }
}


<#
.DESCRIPTION
    Finds instances of command invocation with user input, which can be abused for
    command injection.
#>
function Measure-CommandInjection
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    ## Finds CommandAst nodes that invoke PowerShell or CMD with user input
    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.CommandAst]
        if($targetAst)
        {
            if($targetAst.CommandElements[0].Extent.Text -match "cmd|powershell")
            {
                $commandInvoked = $targetAst.CommandElements[1]
                for($parameterPosition = 1; $parameterPosition -lt $targetAst.CommandElements.Count; $parameterPosition++)
                {
                    if($targetAst.CommandElements[$parameterPosition].Extent.Text -match "/c|/k|command")
                    {
                        $commandInvoked = $targetAst.CommandElements[$parameterPosition + 1]
                        break
                    }
                }

                if($commandInvoked -is [System.Management.Automation.Language.ExpandableStringExpressionAst])
                {
                    return $true
                }
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible command injection risk via calling cmd.exe or powershell.exe. Untrusted input can cause " +
                         "arbitrary commands to be run. Input should be provided as variable input directly (such as " +
                         "'cmd /c ping `$destination', rather than within an expandable string."
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.CommandInjection"
            "Severity" = "Warning" }
    }
}


<#
.DESCRIPTION
    Finds instances of Foreach-Object used with non-constant member names, which can be abused for
    arbitrary member access / invocation when supplied with untrusted user input.
#>
function Measure-ForeachObjectInjection
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    ## Finds CommandAst nodes that invoke Foreach-Object with user input
    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.CommandAst]
        if($targetAst)
        {
            if($targetAst.CommandElements[0].Extent.Text -match "foreach|%")
            {
                $memberInvoked = $targetAst.CommandElements[1]
                for($parameterPosition = 1; $parameterPosition -lt $targetAst.CommandElements.Count; $parameterPosition++)
                {
                    if($targetAst.CommandElements[$parameterPosition].Extent.Text -match "Process|MemberName")
                    {
                        $memberInvoked = $targetAst.CommandElements[$parameterPosition + 1]
                        break
                    }
                }

                if((-not ($memberInvoked -is [System.Management.Automation.Language.ConstantExpressionAst])) -and
                   (-not ($memberInvoked -is [System.Management.Automation.Language.ScriptBlockExpressionAst])))
                {
                    return $true
                }
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible property access injection via Foreach-Object. Untrusted input can cause " +
                         "arbitrary properties /methods to be accessed: " + $foundNode.Extent
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.ForeachObjectInjection"
            "Severity" = "Warning" }
    }
}

<#
.DESCRIPTION
    Finds instances of dynamic static property access, which can be vulnerable to property injection if
    supplied with untrusted user input.
#>
function Measure-PropertyInjection
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    ## Finds MemberExpressionAst that uses a non-constant member
    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.MemberExpressionAst]
        $methodAst = $Ast -as [System.Management.Automation.Language.InvokeMemberExpressionAst]
        if($targetAst -and (-not $methodAst))
        {
            if(-not ($targetAst.Member -is [System.Management.Automation.Language.ConstantExpressionAst]))
            {
                ## This is not constant access, therefore dangerous
                return $true
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible property access injection via dynamic member access. Untrusted input can cause " +
                         "arbitrary static properties to be accessed: " + $foundNode.Extent
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.StaticPropertyInjection"
            "Severity" = "Warning" }
    }
}


<#
.DESCRIPTION
    Finds instances of dynamic method invocation, which can be used to invoke arbitrary
    methods if supplied with untrusted input.
#>
function Measure-MethodInjection
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    ## Finds MemberExpressionAst nodes that don't invoke a constant expression
    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.InvokeMemberExpressionAst]
        if($targetAst)
        {
            if(-not ($targetAst.Member -is [System.Management.Automation.Language.ConstantExpressionAst]))
            {
                return $true
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible property access injection via dynamic member access. Untrusted input can cause " +
                "arbitrary static properties to be accessed: " + $foundNode.Extent
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.MethodInjection"
            "Severity" = "Warning" }
    }
}

<#
.DESCRIPTION
    Finds instances of unsafe string escaping, which is then likely to be used in a situation (like Invoke-Expression)
    where it is unsafe to use. methods if supplied with untrusted input.
    [System.Management.Automation.Language.CodeGeneration]::Escape* should be used instead.
#>
function Measure-UnsafeEscaping
{
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    ## Finds replace operators likely being used to escape strings improperly
    [ScriptBlock] $predicate = {
        param ([System.Management.Automation.Language.Ast] $Ast)

        $targetAst = $Ast -as [System.Management.Automation.Language.BinaryExpressionAst]
        if($targetAst)
        {
            if(($targetAst.Operator -match "replace") -and
               ($targetAst.Right.Extent.Text -match '`"|'''''))
            {
                return $true
            }
        }
    }

    $foundNode = $ScriptBlockAst.Find($predicate, $false)
    if($foundNode)
    {
        [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord] @{
            "Message"  = "Possible unsafe use of input escaping. Variables may be used directly for dynamic parameter arguments, " +
                         "splatting can be used for dynamic parameter names, and the invocation operator can be used for dynamic " +
                         "command names. If content escaping is truly needed, PowerShell has several valid quote characters, so  " +
                         "[System.Management.Automation.Language.CodeGeneration]::Escape* should be used instead."
            "Extent"   = $foundNode.Extent
            "RuleName" = "InjectionRisk.UnsafeEscaping"
            "Severity" = "Warning" }
    }
}
# SIG # Begin signature block
# MIIasAYJKoZIhvcNAQcCoIIaoTCCGp0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7Nh7vd96BGRGZVJRJ/A6hoEu
# pAegghWDMIIEwzCCA6ugAwIBAgITMwAAALfuAa/68MeouwAAAAAAtzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODQ1
# WhcNMTgwOTA3MTc1ODQ1WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkJCRUMtMzBDQS0yREJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuCMjQSw3ep1m
# SndFRK0xgVRgm9wSl3i2llRtDdxzAWN9gQtYAE3hJP0/pV/7HHkshYPfMIRf7Pm/
# dxSsAN+7ATnNUk+wpe46rfe0FDNxoE6CYaiMSNjKcMXH55bGXNnwrrcsMaZrVXzS
# IQcmAhUQw1jdLntbdTyCAwJ2UqF/XmVtWV/U466G8JP8VGLddeaucY0YKhgYwMnt
# Sp9ElCkVDcUP01L9pgn9JmKUfD3yFt2p1iZ9VKCrlla10JQwe7aNW7xjzXxvcvlV
# IXeA4QSabo4dq8HUh7JoYMqh3ufr2yNgTs/rSxG6D5ITcI0PZkH4PYjO2GbGIcOF
# RVOf5RxVrwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFJZnqouaH5kw+n1zGHTDXjCT
# 5OMAMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAG7J+Fdd7DgxG6awnA8opmQfW5DHnNDC/JPLof1sA8Nqczym
# cnWIHmlWhqA7TUy4q02lKenO+R/vbmHna1BrC/KkczAyhOzkI2WFU3PeYubv8EjK
# fYPmrNvS8fCsHJXj3N6fuFwXkHmCVBjTchK93auG09ckBYx5Mt4zW0TUbbw4/QAZ
# X64rbut6Aw/C1bpxqBb8vvMssBB9Hw2m8ApFTApaEVOE/sKemVlq0VIo0fCXqRST
# Lb6/QOav3S8S+N34RBNx/aKKOFzBDy6Ni45QvtRfBoNX3f4/mm4TFdNs+SeLQA+0
# oBs7UgdoxGSpX6vsWaH8dtlBw3NZK7SFi9bBMI4wggTtMIID1aADAgECAhMzAAAB
# eXwuV05S4crWAAEAAAF5MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTE3MDgxMTIwMTExNVoXDTE4MDgxMTIwMTExNVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAKgp/tQQyP9VCp6ZAANSj9ywv/mr+FH+XIxUwifOTCuW
# 69uBHMuGK3nKdX64Z4Mmhr3WLxw+x1iqj2+V+1r8p8YbwcPoTBdOIj23W1Zcf9da
# 9S26u6YJvwZ87pj+QPkwuGv+QG90s7jWOEnJ0IcHLzHftrxOo9Cet2J7VnB1T2e/
# Bcyjrr4AksIbUKFhOxAAAbGG0CnzQPUP2aMPV6tjCajcqWrnR0OnvhXEPSek6FZS
# iM9ZmaEAhDab0DnSKg0v5gTivxOWiIOpUTcYQYni+YWdjmUaPQNkzMXeUHBd8guF
# qY+xReh3/4OdCbty4OZWCJW5K4MSiTH851hyHb35gyMCAwEAAaOCAWEwggFdMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBT45H6NHGN8AKrMcwBK0/JtOKrN
# gTBSBgNVHREESzBJpEcwRTENMAsGA1UECxMETU9QUjE0MDIGA1UEBRMrMjI5ODAz
# KzFhYmY5ZTVmLWNlZDAtNDJlNi1hNjVkLWQ5MzUwOTU5ZmUwZTAfBgNVHSMEGDAW
# gBTLEejK0rQWWAHJNy4zFha5TJoKHzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0Ff
# MDgtMzEtMjAxMC5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8wOC0z
# MS0yMDEwLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAb0trfoYN2AsmUGs6iMhaqfay
# 6iqZp+UGNEQB73P7rS/97fjVgGo1HDTHEwy1XmQ8c2uM8m/Tab7OOw+b+QVyPB1G
# 4eicPjaxbzWpplBUf+HUVz07HnpcjwE/dz9ecydX+qcw59Ryr4vfcSL9iuD64C3f
# X/Led2Tf2rAGAAmrRpCj9f6BhiyTK3XGESjX5YriHCerl4yaxOIHGdPyZBexK93z
# CHp4UIUGMhw5UKPNi3DeCNV7b0w/muh1beTLE1ccKVk4X75Fq6aayvkpns04z7nI
# Bbos+8Qlv2gN3w97QhqVx4+9WmuQC1H617fnj7KzMyhzA1x/o0aCnK22Nnd2hzCC
# BbwwggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmS
# JomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UE
# AxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgz
# MTIyMTkzMloXDTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQ
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2aYCAg
# Qpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicquIEn0
# 8GisTUuNpb15S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqel
# cnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U3RQw
# WfjSjWL9y8lfRjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vX
# T2Pn0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8wawJ
# XwPTAgMBAAGjggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK
# 0rQWWAHJNy4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEKU5VZ
# 5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEB
# BEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5
# Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2sPS9M
# uqKoVpzjcLu4tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOl
# VuC4iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOlkU7I
# G9KPcpUqcW2bGvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/Ta
# rtSCMm78pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4lhhc
# yTUWX92THUmOLb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR82zK
# wexwo1eSV32UjaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZlHg6K
# 3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6wQuxO
# 7bN2edgKNAltHIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJjdib
# Ia4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5iR9HO
# iMm4GPoOco3Boz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZo
# NAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkw
# FwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEwNDAz
# MTMwMzA5WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4kD+7R
# p9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMkh53y
# 9GccLPx754gd6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDlKEYu
# J6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gASkdm
# EScpZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68e
# eEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIBpzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzAL
# BgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAUDqyC
# YEBWJ5flJRP8KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8E
# STBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsG
# AQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B
# AQUFAAOCAgEAEJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxt
# YrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBTFd1P
# q5Lk541q1YDB5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxn
# LcVRDupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfrTot/
# xTUrXqO/67x9C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW
# 6J1wlGysOUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H2146So
# dDW4TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD
# 6Svpu/RIzCzU2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2sWo9
# iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1sMpj
# tHhUBdRBLlCslLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/Jmu5J
# 4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSXMIIE
# kwIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMw
# IQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAXl8LldOUuHK
# 1gABAAABeTAJBgUrDgMCGgUAoIGwMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSt
# 1UOFFkdurYGo9Zol6HDkGEsVazBQBgorBgEEAYI3AgEMMUIwQKAWgBQAUABvAHcA
# ZQByAFMAaABlAGwAbKEmgCRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUG93ZXJT
# aGVsbCAwDQYJKoZIhvcNAQEBBQAEggEAKEWDUQKFo6UfYj6LnZ7yE0q5Def7euI7
# tnZo6op624aqDNVIdhT1pIt4k70q9xplpg8QjoOkQWynS4EmPspzxsaMKqkfcEhK
# ugzqSMRsT/fa8Y6ynZvdCHb860rW1aejzKQyrwjr5Q07aYDbxpmTJZQw3pdacETi
# 1ivI4V0W35DaWgblfPh5rfMwv0nVQNnUY7EJJAEWbLmoumWN3s+Nq9Ch6wa5U0i/
# vU2Qf7f19i1MJFjt8TVoCLv30Of0iZwnribr00/cXm+0aWIyrAwlocQXN3wDbYw0
# PZmyhfls1C2sQF3M+Akg58uyzSQEQsH12DZkX5hjF3yipNx+0hHA+qGCAigwggIk
# BgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0ECEzMAAAC37gGv+vDHqLsAAAAAALcwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MDkwMTIwNDk0OFowIwYJ
# KoZIhvcNAQkEMRYEFMuHlpgxsytXnSc/GJTtVTF/5u5qMA0GCSqGSIb3DQEBBQUA
# BIIBAAIaj+TDVSeHgn8EEuKWJ4D6CuG0U9hckj+5czhTiv4cz/7uIJ21ctmfkeUU
# KGJvyFAZcKwJ5j6Qdb0R0IICVkoK9pZI4VI1rj/tzMezn8gPcw/gufZoP8EE2OP1
# JPZSUx6sOtnRzK0aLa4bgWF0JefyDLBptc6pnKasMR3xjzX7KXJuGuqUuQvWP1qo
# EP297BXq6/3HSgOEk53vYw5zrLMXKHqPmMJNV2d6ZI+3lcbzWOXgmnuj0Jz1HfAM
# Yd9JGCsyjiPEIVSnHcsIVEJtXSP0LYJ4KNGoNRFfzomgpFMVRTy3JtqMu8FqzJzU
# 6RmXAt3w9qh+LNktk2ptOeCOamc=
# SIG # End signature block
