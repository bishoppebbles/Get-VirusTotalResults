<#
.SYNOPSIS
    Virus Total Module
.DESCRIPTION
    Powershell Module for interaction with Virus Total's API
.PARAMETER ApiKey
    Your personal VirusTotal key.  It should not be disclosed to anyone that you do not trust.  Do not embed it in scripts or software from which it can be easily retrieved if you care about its confidentiality.
.PARAMETER File
    The file to scan.
.PARAMETER Hash
    The hash of the file to scan.
.NOTES
    File Name : VirusTotal.ps1 incorporates code that is completely copied from David B Heise's VirusTotal.psm1.
    Author    : David B Heise, Sam Pursglove
.LINK
    https://github.com/DBHeise/Powershell/blob/master/Modules/VirusTotal/VirusTotal.psm1
.EXAMPLE

#>

Add-Type -AssemblyName System.Security

param 
(
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='Enter your VirusTotal API key.')]
    [string]$ApiKey,
    [Parameter(Position=1,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Provide the file to scan.')]
    [System.IO.FileInfo]$File,
    [Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Provide the hash of the file to scan.')]
    [string]$Hash
)

####################################################################
#
# The following functions were written by David B Heise (@DBHeise)
# and are part of the VirusTotal PowerShell Module <VirusTotal.psm1>:
#   Set-VTApiKey
#   Get-VTApiKey
#   Get-VTReport
#   Invoke-VTScan
#   New-VTComment
#   Invoke-VTRescan
# 
# They are available for download from:
#   https://archive.codeplex.com/?p=psvirustotal
# 
# It was released under the Microsoft Public License (Ms-PL)
#
####################################################################

function Set-VTApiKey {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][ValidateNotNull()][String] $VTApiKey,
    [String] $vtFileLocation = $(Join-Path $env:APPDATA 'virustotal.bin'))
    $inBytes = [System.Text.Encoding]::Unicode.GetBytes($VTApiKey)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($inBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($vtfileLocation, $protected)
}

function Get-VTApiKey {
    [CmdletBinding()]
    Param([String] $vtFileLocation = $(Join-Path $env:APPDATA 'virustotal.bin'))
    if (Test-Path $vtfileLocation) {
        $protected = [System.IO.File]::ReadAllBytes($vtfileLocation)
        $rawKey = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::Unicode.GetString($rawKey)
    } else {
        throw "Call Set-VTApiKey first!"
    }
}

function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Uri] $uri,
    [Parameter(ParameterSetName="ipaddress", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $ip,
    [Parameter(ParameterSetName="domain", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $domain
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/report'
        $IPUri = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
        $DomainUri = 'http://www.virustotal.com/vtapi/v2/domain/report'
       
        function Get-Hash(
            [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
            [String] $hashType = 'sha256')
        {
          $stream = $null;  
          [string] $result = $null;
          $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
          $stream = $file.OpenRead();
          $hashByteArray = $hashAlgorithm.ComputeHash($stream);
          $stream.Close();

          trap
          {
            if ($null -ne $stream) { $stream.Close(); }
            break;
          }

          # Convert the hash to Hex
          $hashByteArray | ForEach-Object { $result += $_.ToString("X2") }
          return $result
        }
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $h = Get-Hash -file $file
            Write-Verbose -Message ("FileHash:" + $h)
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $h; apikey = $VTApiKey}
            }
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        "uri" {
            $u = $UriUri
            $method = 'POST'
            $body = @{ resource = $uri; apikey = $VTApiKey}
            }
        "ipaddress" {
            $u = $IPUri
            $method = 'GET'
            $body = @{ ip = $ip; apikey = $VTApiKey}
        }
        "domain" {            
            $u = $DomainUri
            $method = 'GET'
            $body = @{ domain = $domain; apikey = $VTApiKey}}
        }        

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTScan {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Uri] $uri
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/scan'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/scan'
        [byte[]]$CRLF = 13, 10

        function Get-AsciiBytes([String] $str) {
            return [System.Text.Encoding]::ASCII.GetBytes($str)            
        }
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = New-Object System.IO.MemoryStream

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $u = $fileUri
            $method = 'POST'
            $boundary = [Guid]::NewGuid().ToString().Replace('-','')
            $ContentType = 'multipart/form-data; boundary=' + $boundary
            $b2 = Get-AsciiBytes ('--' + $boundary)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="apikey"'))
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes $VTApiKey)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
            $body.Write($b, 0, $b.Length)
            $body.Write($CRLF, 0, $CRLF.Length)            
            $b = (Get-AsciiBytes 'Content-Type:application/octet-stream')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = [System.IO.File]::ReadAllBytes($file.FullName)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            
            $b = (Get-AsciiBytes '--')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            
                
            Invoke-RestMethod -Method $method -Uri $u -ContentType $ContentType -Body $body.ToArray()
            }
        "uri" {
            $h = $uri
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            Invoke-RestMethod -Method $method -Uri $u -Body $body
            }            
        }                        
    }    
}

function New-VTComment {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $Comment
    )

    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/comments/put'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey; comment = $Comment}

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTRescan {
 [CmdletBinding()]
    Param( 
    [String] $VTApiKey = (Get-VTApiKey),
    [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey}
        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}


function Remove-VTApiKey {
    [CmdletBinding()]
    Param([String] $vtFileLocation = $(Join-Path $env:APPDATA 'virustotal.bin'))
    if (Test-Path $vtfileLocation) {
        Remove-Item $vtFileLocation
    } else {
        throw "VTApiKey does not exist"
    }
}


$secStrApiKey = Read-Host 'Enter VirusTotal API Key' -AsSecureString
Set-VTApiKey $([System.Net.NetworkCredential]::new('', $secStrApiKey).Password)

$processes = Get-Process | Where-Object {$_.Path -notlike ''}

$hashedProcesses = $(foreach ($process in $processes) {
        Get-FileHash $process.Path -ErrorAction SilentlyContinue | 
            Select-Object Hash -ExpandProperty Hash
}) | Sort-Object | Get-Unique -AsString

<# NOTES
$proc = Get-Process
foreach($p in $proc) {
    Add-Member -InputObject $p -NotePropertyName 'Hash' -NotePropertyValue (Get-FileHash $p.Path).Hash
}
#>

# rate limit to $queries/min
$count = 0
$queries = 4

$hashOutput = foreach ($hash in $hashedProcesses) {
    Get-VTReport -hash $hash 
    $count++
    if (($count % $queries) -eq 0) {
        $count = 0
        Start-Sleep -Seconds 60
    }
}

Remove-VTApiKey
