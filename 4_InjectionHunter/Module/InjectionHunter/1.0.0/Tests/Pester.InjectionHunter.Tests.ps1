﻿function RunRuleForCommand
{
    param([String] $Command)

    $outputPath = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName() + ".ps1")
    try
    {
        Set-Content -Path $outputPath -Value $Command

        Invoke-ScriptAnalyzer -Path $outputPath `
            -CustomizedRulePath (Resolve-Path $PSScriptRoot\..\InjectionHunter.psm1) `
            -ExcludeRule PS*

    }
    finally
    {
        Remove-Item $outputPath
    }
}

Describe "Tests for expression injection" {

    It "Should detect Invoke-Expression" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Invoke-Expression "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionRisk.InvokeExpression"
    }

    It "Should detect Invoke-Expression alias" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                iex "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionRisk.InvokeExpression"
    }

    It "Should detect InvokeScript" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                $executionContext.InvokeCommand.InvokeScript("Get-Process -Name $UserInput")
            }
        }
        $result.RuleName | Should be "InjectionRisk.InvokeScript"
    }

    It "Should detect CreateNestedPipeline" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                $host.Runspace.CreateNestedPipeline("Get-Process -Name $UserInput", $false).Invoke()
            }
        }
        $result.RuleName | Should be "InjectionRisk.CreateNestedPipeline"
    }

    It "Should detect AddScript" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                [PowerShell]::Create().AddScript("Get-Process -Name $UserInput").Invoke()
            }
        }
        $result.RuleName | Should be "InjectionRisk.AddScript"
    }
}

Describe "Tests for code injection" {

    It "Should detect Add-Type injection" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Add-Type "public class Foo { $UserInput }"
            }
        }
        $result.RuleName | Should be "InjectionRisk.AddType"
    }

    It "Should detect Add-Type injection w/ parameter" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)
                Add-Type -TypeDefinition "public class Foo { $UserInput }"
            }
        }
        $result.RuleName | Should be "InjectionRisk.AddType"
    }

    It "Should detect Add-Type injection w/ variable" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                $code = "public class Foo { $UserInput }"
                Add-Type -TypeDefinition $code
            }
        }
        $result.RuleName | Should be "InjectionRisk.AddType"
    }

    It "Should allow Add-Type w/ constant expression variable" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                $code = "public class Foo { Bar }"
                Add-Type -TypeDefinition $code
            }
        }
        $result | Should be $null
    }

    It "Should allow Add-Type w/ constant expression inline" {
        $result = RunRuleForCommand {
            function Invoke-InvokeExpressionInjection
            {
                param($UserInput)

                Add-Type -TypeDefinition "public class Foo { Bar }"
            }
        }
        $result | Should be $null
    }
}


Describe "Tests for command injection" {

    It "Should detect PowerShell injection" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                powershell -command "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionRisk.CommandInjection"
    }

    It "Should detect PowerShell injection w/o parameter" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                powershell "Get-Process -Name $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionRisk.CommandInjection"
    }

    It "Should detect CMD injection" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                cmd /c "ping $UserInput"
            }
        }
        $result.RuleName | Should be "InjectionRisk.CommandInjection"
    }

    It "Should allow non-injected commands" {
        $result = RunRuleForCommand {
            function Invoke-ExploitableCommandInjection
            {
                param($UserInput)

                cmd /c "ping localhost"
            }
        }
        $result | Should be $null
    }
}

Describe "Tests for script block injection" {

    It "Should detect ScriptBlock.Create injection" {
        $result = RunRuleForCommand {
            function Invoke-ScriptBlockInjection
            {
                param($UserInput)

                ## Often used when making remote connections

                $sb = [ScriptBlock]::Create("Get-Process -Name $UserInput")
                Invoke-Command RemoteServer $sb
            }
        }
        $result.RuleName | Should be "InjectionRisk.Create"
    }

    It "Should detect NewScriptBlock injection" {
        $result = RunRuleForCommand {
            function Invoke-ScriptBlockInjection
            {
                param($UserInput)

                ## Often used when making remote connections

                $sb = $executionContext.InvokeCommand.NewScriptBlock("Get-Process -Name $UserInput")
                Invoke-Command RemoteServer $sb
            }
        }
        $result.RuleName | Should be "InjectionRisk.NewScriptBlock"
    }
}

Describe "Tests for method injection" {

    It "Should detect Foreach-Object injection" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object $UserInput
            }
        }
        $result.RuleName | Should be "InjectionRisk.ForeachObjectInjection"
    }

    It "Should allow Foreach-Object w/ script block" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object { $_.Name }
            }
        }
        $result | Should be $null
    }

    It "Should allow Foreach-Object w/ constant member access" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                Get-Process | Foreach-Object "Name"
            }
        }
        $result | Should be $null
    }

    It "Should detect static property injection" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                [DateTime]::$UserInput
            }
        }
        $result.RuleName | Should be "InjectionRisk.StaticPropertyInjection"
    }

    It "Should detect method injection w/ parens" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                (Get-Process -Id $pid).$UserInput()
            }
        }
        $result.RuleName | Should be "InjectionRisk.MethodInjection"
    }

    It "Should detect method injection w/ Invoke" {
        $result = RunRuleForCommand {
            function Invoke-MethodInjection
            {
                param($UserInput)

                (Get-Process -Id $pid).$UserInput.Invoke()
            }
        }
        $result.RuleName | Should be "InjectionRisk.StaticPropertyInjection"
    }

}

Describe "Tests for string expansion injection" {

    It "Should detect ExpandString injection via ExecutionContext" {
        $result = RunRuleForCommand {
            function Invoke-ExpandStringInjection
            {
                param($UserInput)

                ## Used to attempt a variable resolution
                $executionContext.InvokeCommand.ExpandString($UserInput)
            }
        }
        $result.RuleName | Should be "InjectionRisk.ExpandString"
    }

    It "Should detect ExpandString injection via SessionState" {
        $result = RunRuleForCommand {
            function Invoke-ExpandStringInjection
            {
                param($UserInput)

                ## Used to attempt a variable resolution
                $executionContext.SessionState.InvokeCommand.ExpandString($UserInput)
            }
        }
        $result.RuleName | Should be "InjectionRisk.ExpandString"
    }

}

Describe "Tests for unsafe excaping" {

    It "Should detect unsafe escaping - single quotes" {
        $result = RunRuleForCommand {
            function Invoke-UnsafeEscape
            {
                param($UserInput)

                $escaped = $UserInput -replace "'", "''"
                Invoke-ExpressionHelper "Get-Process -Name '$escaped'"
            }
        }
        $result.RuleName | Should be "InjectionRisk.UnsafeEscaping"
    }

    It "Should detect unsafe escaping - double quotes" {
        $result = RunRuleForCommand {
            function Invoke-UnsafeEscape
            {
                param($UserInput)

                $escaped = $UserInput -replace '"', '`"'
                Invoke-ExpressionHelper "Get-Process -Name `"$escaped`""
            }
        }
        $result.RuleName | Should be "InjectionRisk.UnsafeEscaping"
    }
   
}
# SIG # Begin signature block
# MIIasAYJKoZIhvcNAQcCoIIaoTCCGp0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaLR/0nwJxYZMO1N7D44lHe+D
# jTSgghWDMIIEwzCCA6ugAwIBAgITMwAAALfuAa/68MeouwAAAAAAtzANBgkqhkiG
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTX
# eonK1YwkY/XDK+R7sPZoJOr1BDBQBgorBgEEAYI3AgEMMUIwQKAWgBQAUABvAHcA
# ZQByAFMAaABlAGwAbKEmgCRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUG93ZXJT
# aGVsbCAwDQYJKoZIhvcNAQEBBQAEggEAkHCrAyYvWMfyiyecoZ1/66epZ91YfcXB
# U04FKvjvPzBCtNoORdshjh7xV5CeQkmyeMubOJPZ1QfjsljnyRolx5BkccAbmPg3
# Pcl/cP+xsDIk0ghXufSbKFLCCEpYdcH11amuN06/23Lkv7w1UhjqsZhS5tV5+7rS
# WV3sJqea4XLjxfSjvrUvRp4gHq9TCsiGTkpp2FSXfPr3l1Uzw3byLA207expo9vB
# +iPDuQZVpcdvKxs9eJYhxyuTTygZFYTpc3TgvsBDYGd7+93qPghxCyHSqyuxC5bh
# F9CrGKbdblm5gE/qHgTDirLP6sTgDo+kgjD9KWWHonnvX+GfWKZJJ6GCAigwggIk
# BgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0ECEzMAAAC37gGv+vDHqLsAAAAAALcwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MDkwMTIwNTEyMFowIwYJ
# KoZIhvcNAQkEMRYEFGSUFl3InqVkja7y+uC6Uafv/U2wMA0GCSqGSIb3DQEBBQUA
# BIIBAECpR7FsgFxf1sQ12qI2xBAj2ws1cRwV/gfO/L14PFKhhcXtfi09AHYIbS0y
# I8Hj4J4OlwIZazq66rDQrrUboCzm092aAW9yDJCOM23e4ICqzNP0i1z6Vq5HGsRt
# sXI8Yk7rN1DnV6HeZrvQhGiGHTqKitmZ/hIe5CwsVsgsnbRmV7aH+UvLsC9iqxOr
# pKalAZ2QegPZ8Mz1gmE75pVHH2n6nt0y8jDPwfisiyfui8mSU07d04bWkzBx6ELv
# sMmn05F4m/TkJ/mrRaCsg9oylNpfRCdrAGytEAvH1B0WfmNBuThQpUCsfcXMgCa9
# alFw9mM2mBq/CK5YulwlXkaF2W8=
# SIG # End signature block
