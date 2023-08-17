<#
.SYNOPSIS
    Virus Total Module
.DESCRIPTION
    Powershell Module for interaction with Virus Total's API
.PARAMETER CsvFile
    The CSV file to import containing the process name, path, and hash information.
.PARAMETER ForceClearApiKey
    Clear an existing API key entry so a new one can be entered.
.NOTES
    File Name : VirusTotal.ps1 incorporates code that is completely copied from David B Heise's VirusTotal.psm1.
    Author    : David B Heise, Sam Pursglove
.LINK
    https://github.com/DBHeise/Powershell/blob/master/Modules/VirusTotal/VirusTotal.psm1
.EXAMPLE

#>

Add-Type -AssemblyName System.Security

Param (
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='Provide the file to scan.')]
    [System.IO.FileInfo]$CsvFile,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Clear the existing API key.')]
    [switch]$ForceClearApiKey
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

        Invoke-RestMethod -Method $method -Uri $u -Body $body
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

        Invoke-RestMethod -Method $method -Uri $u -Body $body
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
        
        Invoke-RestMethod -Method $method -Uri $u -Body $body
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


function Import-ExeCsvData {
    Param([Parameter(Position=0,Mandatory=$true)][System.IO.FileInfo]$file)

    $exes = Import-Csv $file | 
                Select-Object Name,Path,Hash,Positives,Total,ScanDate,ScanResults | 
                Where-Object {$_.Hash -notlike ''}
    
    # Modify exe file paths if C:\User\<username>\... is included so there's a single, unique path C:\User\*\... for all
    foreach($e in $exes) {
        if($e.Path -imatch '^C:\\Users\\') {
            $e.Path = $e.Path -ireplace '(^C:\\Users\\)(\w+)(.+)','$1*$3'
            }
    }

    $exes | Sort-Object Path,Hash -Unique
}


[SecureString]$secStrApiKey | Out-Null

if($ForceClearApiKey) {
    $secStrApiKey.Clear()
}

# if the script is run multiple times only prompt for the API key the first time (or if it is force cleared)
if($secStrApiKey.Length -eq 0) {
    $secStrApiKey = Read-Host 'Enter VirusTotal API Key' -AsSecureString
    Set-VTApiKey $([System.Net.NetworkCredential]::new('', $secStrApiKey).Password)
}

<# NOTES
$proc = Get-Process
foreach($p in $proc) {
    Add-Member -InputObject $p -NotePropertyName 'Hash' -NotePropertyValue (Get-FileHash $p.Path).Hash
}
#>
 
$sortedUniqueExes = Import-ExeCsvData $CsvFile  

# rate limit to $queries/min
$count = 0      # tracks VT request rate limit
$queries = 200

$counter = 0    # tracks Write-Progress

foreach ($entry in $sortedUniqueExes) {
    $activity        = "Get-VTReport ($($count) of $($sortedUniqueExes.Length))"
    $currentStatus   = "Getting results for $($entry.Path)"
    $percentComplete = [int](($counter/$sortedUniqueExes.Length)*100)
    Write-Progress -Activity $activity -Status $currentStatus -PercentComplete $percentComplete


    $report = Get-VTReport -hash $entry.Hash

    if ($report.response_code -eq 1) {
        $entry.Positives = [int]$report.positives
        $entry.Total     = [int]$report.total
        $entry.ScanDate  = [datetime]$report.scan_date

        # get A/V vendor name and result for positive results
        if($report.positives -gt 0) {
            $r = New-Object System.Collections.ArrayList

            $report.scans.PSObject.Properties |
                ForEach-Object {
                    if($_.Value.detected) {
                        $r.Add("$($_.Name)=$($_.Value.result)") | Out-Null
                    }
                }
            $entry.ScanResults = $r
        }

    } elseif ($report.response_code -eq 0) {
        $entry.Positives = 0
        $entry.Total     = 0

    } else {
        Write-Output "VT response code other than 0 or 1 was returned"
        Write-Output "$($entry.Name): $($entry.Hash)"
    }
    
    # rate limit the submissions
    $count++
    if (($count % $queries) -eq 0) {
        Write-Progress -Activity $activity -Status $currentStatus -PercentComplete $percentComplete -CurrentOperation "Rate limit reached. Pausing."
        $count = 0
        Start-Sleep -Seconds 10
    }
}

$sortedUniqueExes | Export-Csv -Path "VTDB_$(Get-Date -Format FileDateUniversal).vtdb" -NoTypeInformation

Remove-VTApiKey