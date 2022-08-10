Function Get-MissingMsUpdates {
    <#
   .SYNOPSIS
       Uses the Windows Update Agent (WUA) to scan offline systems for security updates without connecting to Windows Update or Windows Server Update Services (WSUS). 
   .EXAMPLE
       Get-MissingMsUpdates -UpdateFile C:\Temp\wsusscn2.cab
       This command uses the wsusscn2.cab file that is stored in C:\Temp to query the system for missing updates. The output of the script is stored in the default location, C:\Users\[USERNAME]\Desktop\MsScanReport.csv.
   .EXAMPLE
       Get-MissingMsUpdates -UpdateFile C:\Temp\wsusscn2.cab -OutFile C:\Temp\MsScanReport.csv
       This command uses the wsusscn2.cab file that is stored in C:\Temp to query the system for missing updates. The output of the script is stored in the location identified after the OutFile parameter, C:\Temp\MsScanReport.csv.
   #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        $UpdateFile,
        [Parameter(Mandatory = $false)]
        $OutFile = "$env:USERPROFILE\Desktop\MsScanReport.csv"
    )
   
    #Perform switch operation on based on user privilege status.
    Switch (([security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
           
        #If the user is running as an administrator, write confirmation output to the shell.
        $TRUE { Write-Host "YOU ARE CURRENTLY RUNNING WITH THE REQUIRED PRIVILEGES!" -ForegroundColor Green }
   
        #If the user is not running as an administrator, output error to the shell.
        $FALSE { Write-Host "PLEASE RERUN WITH ADMINISTRATIVE PRIVILEGES!" -ForegroundColor Red; PAUSE; EXIT }
    }
   
    #Create a session in which the caller can perform operations that involve updates.
    $updateSession = New-Object -ComObject Microsoft.Update.Session 
   
    #Add the registration of the update service with Windows Update Agent (WUA).
    $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager 
   
    #Register a scan package as a service with Windows Update Agent (WUA).
    $updateService = $updateServiceManager.AddScanPackageService("Offline Sync Service", $UpdateFile, 1) 
   
    #Create update searcher interface.
    $updateSearcher = $updateSession.CreateUpdateSearcher()
   
    #Identify server selection method as '3' (ssOthers), which configures the windows agent to 'search another server, to be specified by other means'.
    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/07e2bfa4-6795-4189-b007-cc50b476181a
    $updateSearcher.ServerSelection = 3
   
    #Convert the service ID to a string. This fixes an issue where Windows 10 truncates the service ID.
    $updateSearcher.ServiceID = [string]$updateService.ServiceID
   
    #Perform a synchronous search for updates. 'IsInstalled=0' finds updates that are not installed.
    $searchResult = $UpdateSearcher.Search("IsInstalled=0")
   
    #Return discovered updates.
    $requiredUpdates = $SearchResult.Updates 
   
    if ($requiredUpdates.Count -eq 0) {
   
        #If the required update count is 0, write that there are not applicable updates to the shell.
        Write-Host "There are no applicable updates." -ForegroundColor Green

    }
    else {
   
        #If the required update count is greater than 0, loop through each update to create a custom powershell object.
        $requiredUpdates | ForEach-Object {
            [PSCustomObject]@{
                Title       = $_.Title
                Severity    = $_.MsrcSeverity
                Description = $_.Description
                URL         = $_.SupportUrl
            }

        } | Export-Csv $OutFile -NoTypeInformation

    }
   
    #Determine if there is a ScanFile directory.
    if (Test-Path C:\Windows\SoftwareDistribution\ScanFile) {
   
        #If the ScanFile directory exists, remove its contents.
        Remove-Item C:\Windows\SoftwareDistribution\ScanFile\* -Recurse

    }
    
}

# SIG # Begin signature block
# MIItEwYJKoZIhvcNAQcCoIItBDCCLQACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA6g3hwO2/CYjDT
# AuPnMsY7IKgW9hJPYtZbktoQTzSeKaCCJgMwggWDMIIDa6ADAgECAg5F5rsDgzPD
# hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJv
# b3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFs
# U2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsT
# F0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMw
# EQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvF
# tonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBt
# QmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe
# +bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g
# 6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6
# frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK
# 8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGX
# hAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoo
# jRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI
# 9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1v
# uC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYD
# VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0G
# CSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZip
# W6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlez
# orM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZU
# ACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbv
# GhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA
# 6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF
# 0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSq
# aUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlX
# HKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+
# S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRb
# H60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmk
# EDCCBZAwggN4oAMCAQICEAWbG1eejiEy4jkHvad3dVwwDQYJKoZIhvcNAQEMBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTEzMDgwMTEyMDAwMFoXDTM4MDExNTEyMDAwMFowYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE9
# 8orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9S
# H8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g
# 1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RY
# jgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgD
# EI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNA
# vwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDg
# ohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQA
# zH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOk
# GLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHF
# ynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gd
# LfXZqbId5RsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
# AYYwHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMA0GCSqGSIb3DQEBDAUA
# A4ICAQC7Ydl9qWy+F8SRG8OhogCN42RoD1bPd65w+f2aSpm5yXhcDAxf5OYUKVYL
# NkldRGPgrZyWGGYbIw09eelta9ZU+NI8wUNArh1Q9VL8kDu7mJlpa8fBp6hopCfc
# nfknrjCFufZnTTo+j1k5IlNE68hdA8rtUHp9YiEKgMhzZtGgBWBf6KW0p6+o9201
# nHxaitaiOJnzeIv0TdIgC94E7oybR4FyDcAUMu8wWS6u4HHyVuRql2+SUG2WjWh6
# mrI2FHoG8iS5CRFQ1wixuIl6hCNhQinlo82iIEHX0Zxk2eomoYsU10wZslBBcT0/
# TXAjhgxK3IHSzDKUhA0ICZccT8DuayB0MNLgOTQQhSEVAQjoVTLecUnZKBdQTea+
# TdF1rNDK+0G4Q6Wq08MFRE8sNpvi+uJFuCNTbAZvZ1V/RrVMP24oWnkm0qSoYpfS
# HuLtSou8G/1HSg3fZ2Z+sltB0Dvk9Dv0BGPp78JUAFGgiirJznjM1eqHBBizzq9J
# iK/zkpm2s+ZhD9KFAOdQGuQblZ0ZobmcsZuxAB7v0A9PQmzJCrzuQ/o6caXITSal
# Nf2JXbyFYh0y0qArVO2aV8Hb+hDPGbeLShuPAbYnlVPotoltW7xo1CPoi1GiVvnw
# poCg1h6zvA8PU3UpquoTd+TejIEhrQcQRxGthz0H0XW8z/NmfjCCBlkwggRBoAMC
# AQICDQHsHJJA3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xv
# YmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNV
# BAMTCkdsb2JhbFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBb
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UE
# AxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691g1+pR1LH
# YTpjfDkjeW10/DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3RKErBLLu5
# cPJyroz3mVpddq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8ijtuasSI
# 8O6X9tzzGKBLmRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRTB4uZbrhU
# mYqoMZI78np9/A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl69FWqS69
# +1g9tYX6U5lNW3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZJTTtlu/4
# Z+oIvo9Jev+QsdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2bVb+ih0J
# PiQOZybH/LINoJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZvGxjVNupk
# rs799QXm4mbQDgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB3pkl+XFu
# 6ZxdAkxgPM8CjwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN22TwRZ+6
# wT9Uo9h2ApVsao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0ZsJfqjFCR
# ba9Xhn4QNx1rGhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9ZZYwHwYD
# VR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEEMjAwMC4G
# CCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDYG
# A1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1y
# Ni5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQB/4ojZV2crQl+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZrGUBJJQge
# 5Jv31qQNjx6W8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP7MJWZR29
# f/begsi3n2HTtUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBxdnDSD5bz
# 6jdXlJEYr9yNmTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3RafXKGNbMC
# Vx+LnPy7rEze+t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h1pnO6X1L
# lizMFmsYzeRZN4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3ygxayvUQbw
# EccdMMVRVmDofJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh/mIQ7R0w
# /PbM6kgnfIt1Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUgDhtRoNRj
# qoPqbHJhSsn6Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2ce1SIf4+
# 9p+fORqurNIveiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5JeIsEH6B
# +Q2Up33ytQn12GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBmgwggRQoAMCAQIC
# EAFIkD3CirynoRlNDBxXuCkwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24g
# VGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjIwNDA2MDc0MTU4WhcN
# MzMwNTA4MDc0MTU4WjBjMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2ln
# biBudi1zYTE5MDcGA1UEAwwwR2xvYmFsc2lnbiBUU0EgZm9yIE1TIEF1dGhlbnRp
# Y29kZSBBZHZhbmNlZCAtIEc0MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
# AYEAwsncA7YbUPoqDeicpCHbKKcd9YC1EnQj/l4vwxpdlrIgGRlQX3YjJjXGIeyU
# 77WiOsWQgZsh7wsnpOMXZDvak9RWLzzXWPltrMAvkHgjScD4wY9wE9Rr3yaIWnZ7
# SPfhpKbvCxrzJVQPgJ4jEhIT0bD3AuMrDf9APgBCQ94a70z0h6nynjzQBufiY9Lr
# TFvdXViU0+WlOSiqB152IzD8/H+YDcVlbRvVdEU6RrCiFnXeosIqcHy2drzZG666
# XZz2h5XOqqjitaOxk25ApZsQiHYWTjSh/J7x4RpU0cgkV5R2rcLH7KOjlnXixihr
# AgXoS7m14FIreAGMKjEsTOgF5W+fD4QmLmhs+stNGXwYwf9qGqnLvqN1+OnIGLLM
# 3S9BQCAcz4gLF8mwikPL4muTUfERvkK8+FHy2gACvggYKAUnxNw7XXcpHhnUQSpm
# fbRSc1xCpZDTjcWjqjfOcwGUJBlCQ9GUj0t+3cttvBtOe/mqCyJLSYBJcBstT940
# YD69AgMBAAGjggGeMIIBmjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwHQYDVR0OBBYEFFtre/RwdAjBDSrI7/HEuUDSSsb9MEwGA1UdIARF
# MEMwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEB
# BIGDMIGAMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9j
# YS9nc3RzYWNhc2hhMzg0ZzQwQwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xv
# YmFsc2lnbi5jb20vY2FjZXJ0L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgw
# FoAU6hbGaefjy1dFOTOk8EC+0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDov
# L2NybC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqG
# SIb3DQEBCwUAA4ICAQAuaz6Pf7CwYNnxnYTclbbfXw2/JFHjGgaqVQTLYcHvZXGu
# C/2UJFcAx+T2DLwYlX0vGWpgM6a+0AhVVgS24/4eu+UQdlQ7q1whXio1TUbLpky6
# BEBgYCzb0/ad3soyEAx4sLtWxQdLcLynD6tyvI3L6+7BTGvZ+pihdD7pqMh5fHZ3
# SP3P4/ANwenDkuAHDBMvP2t/NdnVt+5vfFjA8T8MGbICo0lMnATD8LSXp+BNaiW6
# NBZiZsh4vGlzql9yojVYHibrvzIUqhJ66/SWa39yrOqnOQgzATY+YSR+EZ0RHnYi
# VONAuy6GDHaeadLEHD2iC4yIBANU3ukbF/4sK57Z1lsiOPxkQIbNF3/hqZ+5v5JB
# qG8mavQPKLBAkZAvTrZ2ULxNI9l/T2uTKads59AwPqmTH8JQKznFsvhNJyTR/XbY
# vvmT9KlUCtV2WNE8nuoa6CTE+zbxL1nTksPsy2BSHhxGJQj/ftmTrhSVqIaKBy5U
# i3NMNxU4UFaH8U+uHI/JoWwvC/y7HG8tvaq262gj8O2UJxRjy6z0Z4osgdMUEhgB
# P4R6ruxHYD9oWJnJSsKhmRUFwq3eou/Xp1V8vIQbTZS7jkqFRNmBPaqjJVVfpGvN
# NmwA+f9y3lrs/8mgQZYaQGqFkRyvdWOoy1oztZQzfrKND3O+h/yvOnMfeyDbcjCC
# BrAwggSYoAMCAQICEAitQLJg0pxMn17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM
# 6z2Bl3DFu8SFJjCfpI5o2Fz16zQkB+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGR
# zIEDPk1wJGSzjeIIfTR9TIBXEmtDmpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK
# 4J0JwGWn+piASTWHPVEZ6JAheEUuoZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1M
# ghFIUmjeEL0UV13oGBNlxX+yT4UsSKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC
# 9KejAw50pa85tqtgEuPo1rn3MeHcreQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1E
# GpIQgY+wOwnXx5syWsL/amBUi0nBk+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5Nh
# NFy8k0UogzYqZihfsHPOiyYlBrKD1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvet
# CB51pmXMu+NIUPN3kRr+21CiRshhWJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCT
# dhSmW0tddGFNPxKRdt6/WMtyEClB8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5A
# R1/JgVBzhRAjIVlgimRUwcwhGug4GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6
# tuyMMgkCzGw8DFYRAgMBAAGjggFZMIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBRoN+Drtjv4XxGG+/5hewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3Js
# MBwGA1UdIAQVMBMwBwYFZ4EMAQMwCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4IC
# AQA6I0Q9jQh27o+8OpnTVuACGqX4SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2e
# o3wm1Te8Ol1IbZXVP0n0J7sWgUVQ/Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5
# iJqKisG2vaFIGH7c2IAaERkYzWGZgVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3Sjr
# XyahlVhI1Rr+1yc//ZDRdobdHLBgXPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq
# 8aI+20O4M8hPOBSSmfXdzlRt2V0CFB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92
# NyyFPxrOJukYvpAHsEN/lYgggnDwzMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5
# ceG+nKcKBtYmZ7eS5k5f3nqsSc8upHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6
# /To/RabE6BaRUotBwEiES5ZNq0RA443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuP
# iAsNvzv0zh57ju+168u38HcT5ucoP6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdL
# oNMHAmpqQDBISzSoUSC7rRuFCOJZDW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh
# +Vc7tJwD7YZF9LRhbr9o4iZghurIr6n+lB3nYxs6hlZ4TjCCB2cwggVPoAMCAQIC
# EAoM4tW4X1QSg34XMarCQN4wDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0y
# MjA2MjQwMDAwMDBaFw0yMzA4MjMyMzU5NTlaMGwxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQIEwxQZW5uc3lsdmFuaWExEjAQBgNVBAcTCUxhbmNhc3RlcjEYMBYGA1UEChMP
# U2VjdXJlU3RydXggTExDMRgwFgYDVQQDEw9TZWN1cmVTdHJ1eCBMTEMwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDmorNUT1Gd5GDuBjSSV878IGUj8jPi
# J50C4ocGleE0l98qqFv62oyE9V+H1vCpgC3/PKDv0jU25J6Um3CpOfAzT9ge9Fb/
# OL33QshadoVXBPOJxIFRBhZlO1+VZmwYP3U9Q7+gaTMqwzCNwW8QtL5l8Csp90+4
# rS6hb7cfNSBMOQxUZkpRq9f1nduY57rBkVWQfpiViMupAZIuTOjlQDIuy/dObVwr
# JFbYwCcquQqqnkUyz1lUtbpGYddneFizmG7bsbNWIp0IK/hznXBbU2sPX/ZDKslN
# lMToI/SML+ULhRTAJti/Z3jl6xJA1ea2FpkGmipWmXfH8xdsy8eB0EdguG7aWwW7
# hSJjRq3dTDQF0o4CsmcHcTQGgEwswNbY17iqMFIw7uxz8rNyjacX+lQjabI2J58G
# vqTRvj2QsljqMg5Ix2xRaxOilVRMAokFSo+ozz84f3qUEyDBy+0zmZyNN6mVboEM
# Vjcknqb/mtlQUZSdORnK+HFmjny/ufWJHCEdQqk1xkVTISp2UdrAv7TXm6DFlySp
# VRNzRFMuGBvM0Tjm2HO56vmA5rXp86FCWeglQJ6R3eV2hHT/rPbj5CoyOkmOjGQd
# Cx4sgo+XhWocGOUKpNzfB3vb17lSkYy2VGdlNpqwn5rJlxi5jW+FKFY/cRzt+wZb
# MU1BBkW0p1ROzQIDAQABo4ICBjCCAgIwHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHQYDVR0OBBYEFCn+9+Gg2T3L6oGkjYCuAPsOVjguMA4GA1UdDwEB
# /wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBP
# hk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2Rl
# U2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcB
# AQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwG
# CCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAuEF6CYx8RvOWWcK8+Yt36xnzh
# 6w1wLTy3aIpXPSsA/Lg2TEcUu2y+fUZIYQZiSJ2tEgVt5GS3Li9+yOO+wvsWKBu9
# nGjeedunHJSHyiX8JokrRhmXS3DoU2tDzZaRNY/R3GpZLqoR+9qbJjgqKjUKmVJL
# UyXHXkCfZuO+A1oWQ1oY3+RVzbPcb9JurElAs6LqKvZAL8tfCL+/zD1T48Dtbdqs
# btQxc+dlGBQ9uYPKdvtX/if316SC9NYwV5hHKeH1Eys409gh3mJOjV0GndEaodYO
# rsdKAr3A+u6xCD4f4Dtk97vhz85/sQclzW4C8FcvbgHKOEGIBkSKQGpn7HEvx7iL
# o5R90x7w/+q+8liW5v7Kr2V0DvAqTp2PKgYWc3b38QzMltaWP4SZ3Vk0V2QcP2V3
# DgCJ1EvrAySO3Eesek3E7qBTQ2x8qVQ5p7hG8zM2FljWzuEtoZVpGWnh66nYRXuM
# ngAHuyNYxjz8DaQSBYPOYrijgPo71Nw6YRvJDehG4ENGdnWPszqc42jp8TPV29un
# xk4RY5hChEkmgDHMg8OuNaZo/H9q2KNcqh9pJo7QqheKXQlSnqHpAmGqyWYweHfl
# Kzxlud3awL/l86/nJ8ScATvk9PQt6DUT6MLKvIOKk1AEGBWIfzB4zzpCYXidqTNS
# p7xnJ8lapOuPdSHdHzGCBmYwggZiAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQCgzi1bhfVBKD
# fhcxqsJA3jANBglghkgBZQMEAgEFAKBMMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMC8GCSqGSIb3DQEJBDEiBCDFVKsW+sFtT5JH79ZwSKFSoaWWJuwbQUssUS2S
# /AT3izANBgkqhkiG9w0BAQEFAASCAgAtlZ1dE7MFPp2hTIH97zNcIRowtt1xEcTX
# GcCVMo145oKCXQX1DfDZlUHkLmm2lJpywPFI5muv43LgN/7+Hi/hIJ8y6OPJjG7x
# ukQ2e6oVCPVQnemtwZP/QII20wEEcSnwkxTFYmrqmGKL+WzpUltiU0dmQTTnqIF8
# mFPeKPq78mWyciPC6nP3G83UHbRdDcTD4m77DXcZ5xwf7HTH0diCSJCHkA7LAeTZ
# ErxniEgRR3Pv/W1rrM/2k7r6x/5Kxh+a9xSQ44pDjhhayQw46M0fLG73vgjENFvu
# hEJJnSWm15A2CORkrEhQcHFWcvsshSjp1CRu0AJOJAp3FJy6O2Mh11PyS6I9gfjL
# 4W2LeFa2p/ov5D9h+yTRH8aFsQX6hDiJu4ckBXaQjfoQeIybOrgPc8ErJD9bVZGo
# hjZjAVICNmUROu2xC4AmCVluuJ0dlsbT8pBm9XbMJUkNoOyq7Q5HugRSXjQQIYIk
# xaMRES3EMd0QtsoznTxM+WhamxdHNlgGX4YeModsTo4dPWMt/MlzYfGDF7R/hR4W
# 4P14nh3Cx31eJRmR4zb7UL1rwDSqxprehT55Huh+QF8vUVqq2fpSePJNA5JW5FxF
# 9JXWaSabOLuUAkPdPvNVOGLR1xfP4bHw5UYjnacW1DrkDN0PEkncnfvfYLzWlypD
# VuTn6c7/tKGCA2wwggNoBgkqhkiG9w0BCQYxggNZMIIDVQIBATBvMFsxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABSJA9woq8p6EZ
# TQwcV7gpMAsGCWCGSAFlAwQCAaCCAT0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
# ATAcBgkqhkiG9w0BCQUxDxcNMjIwODEwMDIzNTMxWjArBgkqhkiG9w0BCTQxHjAc
# MAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQgSiuV
# lp23HzFAOHoq/qiM1avXR0uTVRODpvyvLwO6yJ4wgaQGCyqGSIb3DQEJEAIMMYGU
# MIGRMIGOMIGLBBQxAw4XaqRZLqssi63oMpn8tVhdzzBzMF+kXTBbMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFs
# U2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQAUiQPcKKvKehGU0M
# HFe4KTANBgkqhkiG9w0BAQsFAASCAYAcO/URxuFsdwpUbsFL98kwulnEf577dSQR
# e7UFi/nS4BwBujL0V8koXfXLQbVKIITA9QiCQ62a5HlQERDy0HWp/sGLWB8ETOGr
# ph1gqTBYPsBsJLYjNFahoR3TY2Vzy0vLPlkpkXjIblnzZadMTyUXPwUDuH9Dwil8
# pjHpkNC82Gcl16n9U/9IJdOWhh6ld6Int8E3SUjER8ZmTE6wEMq7JOm1JYkXZ4yr
# ynGUjDCTt5mtlW3uPK1D1rWkDnbgaPQJ4tJyDha0xMuQSfpNtR+YWicfds2oZf5F
# EZ12oKVHTdAsn4dAqmUt5ctN3CRL/Y9V9Sit2eTlhwvS9VmKiCELySxCZrNmzmbW
# MOsVF2AimvQaS6opx/YLfi/y6+tw7Enndg+7nQWKFoaSp8txTQ9gZFhK/c2AjW2w
# h7xUlC5iHlkq6YAPVa6gHN8u3ksFukCrQm9a10GbmE5VZ1cHWrzHHkGjEsfGJPj9
# 3G1M5naENGeJwBEH6HUI8piPufGLPb0=
# SIG # End signature block
