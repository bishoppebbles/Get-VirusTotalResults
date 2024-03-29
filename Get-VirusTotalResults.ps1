<#
.SYNOPSIS
    This PowerShell cmdlet allows you to batch submit process hashes via the VirusTotal (VT) API.  It incorporates @DBHeise VirusTotal.psm1 for VirusTotal API interaction.  The code uses as input the processes.csv output from the Collect-ADDomainData.ps1 (i.e., FakeHyena) script.
.DESCRIPTION
    This script prompts the user for their VirusTotal API key.  It then imports a CSV file produced from the Collect-ADDomainData.ps1 script by @bishoppebbles that includes process name, path, and hash information.  Get-VirusTotalResults is processed to create unique entries based on the process's path and hash (i.e., if the hash is the same but it was located in a different path there would be two separate entries).  If there is no local json database file, all process file hashes are submitted to VT for analysis.  Note that only hashes are submitted, no file data.  The results are written to a CSV with the following fields: Name, Path, Hash, Positives, Total, ScanDate, ScanResults (A/V scan engine(s) with positive results), Link (VT results link).  A local json database file is also written for optional later reuse.  If a local json database exists from a previous scan, the current process hash data is first compared against this database for any matching results.  Then only the remaining entries are submitted to VT for review.  A new, updated json database file with the total cumulative results are then written to disk for later optional reuse.

    By default the VT API submission rate is limited to 1000 API submissions before the code will sleep for 60 seconds.  This is effectively no rate limit as it's unlikely 1000 submissions will be required in a mostly homogenous enterprise computing environment, at least based on my tests (i.e., there are not going to be that many unique running processes).  However, if you have a small VT API submission rate (e.g., 4/minute) this can be used to slowly submit your process hash data.  This feature hasn't been thoroughly tested.  
.PARAMETER CsvFile
    The CSV file to import containing the process name, path, and hash information.
.PARAMETER VirusTotalDB
    The CSV file to import containing the process name, path, and hash information.
.PARAMETER Queries
    Rate limit for the number of VirusTotal API queries before a 60 second sleep (default = 1000).
.PARAMETER DoNotExportCsvResults
    Switch parameter to not write the CSV results to file.  This would only write a new json database file of the analysis.
.PARAMETER ForceClearApiKey
    Clear an existing API key entry so a new one can be entered.
.NOTES
    File Name : VirusTotal.ps1 - incorporates code that is copied from David B Heise's VirusTotal.psm1.
    Author    : Sam Pursglove, David B Heise (VT API)
    Version   : 0.13
    Date      : 14 March 2024
.LINK
    https://github.com/DBHeise/Powershell/blob/master/Modules/VirusTotal/VirusTotal.psm1
    https://github.com/bishoppebbles/Collect-ADDomainData
.EXAMPLE
    .\Get-VirusTotalResults.ps1 -CsvFile .\processes.csv

    Submits the process hash data taken from the Collect-ADDomainData.ps1 (i.e., FakeHyena) script.  By default it will look for a local JSON VT database file in the current working directory for previous VT queries and use any existing matches from that.  If not present, all values are submited to VT.  An updated new VT JSON database file is written to disk.
.EXAMPLE
    .\Get-VirusTotalResults.ps1 -CsvFile .\process.csv -Queries 4

    Same as the above but rate limits the VT API queries to 4/minute.  The default is set to 1000/minute.
.EXAMPLE
    .\Get-VirusTotalResults.ps1 -CsvFile .\processes.csv -VirusTotalDB ..\vtdb\VTDB_20240209Z.json

    Submits the process hash data taken from the Collect-ADDomainData.ps1 (i.e., FakeHyena) script.  Looks in a non-default location for an existing JSON VT database file for previous VT queries and use any existing matches from that.  An updated new VT JSON database file is written to disk.
#>

Param (
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='Provide the CSV file to scan.')]
    [string]$CsvFile,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Explicitly set the existing local VirusTotal database.')]
    [string]$VirusTotalDB,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Set the number of VT API queries before a 60 second sleep. (default=1000)')]
    [int]$Queries=1000,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Do not export the results to a CSV file.')]
    [switch]$DoNotExportCsvResults,
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
# It was released under the MIT license
#
####################################################################


Add-Type -AssemblyName System.Security

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


# Load running process information produced from the Get-Process PowerShell cmdlet that also includes
# additional code to hashes image files.  This is produced from the FakeHyena code.  Then create unique
# results based on the file hash and image path.  There may be duplicate hashes if the image file is
# located in different paths.
function Import-ExeCsvData {
    Param([Parameter(Position=0,Mandatory=$true)][System.IO.FileInfo]$file)

    $exes = Import-Csv $file | 
                Select-Object Name,Path,Hash,Positives,Total,ScanDate,ScanResults,Link | 
                Where-Object {$_.Hash -notlike ''}
    
    # Modify exe file paths if C:\User\<username>\... is included so there's a single, unique path C:\User\*\... for all
    foreach($e in $exes) {
        if($e.Path -imatch '^C:\\Users\\') {
            $e.Path = $e.Path -ireplace '(^C:\\Users\\)(.+?)(\\.+)','$1*$3'
        }
    }

    $exes | Sort-Object Path,Hash -Unique
}


[SecureString]$secStrApiKey | Out-Null

if($ForceClearApiKey) {
    if ($secStrApiKey) {
        $secStrApiKey.Clear()
        Write-Output 'API key was cleared.'
    }
}

# if the script is run multiple times only prompt for the API key the first time (or if it is force cleared)
if(-not $secStrApiKey) {
    $secStrApiKey = Read-Host 'Enter VirusTotal API Key' -AsSecureString
    Set-VTApiKey $([System.Net.NetworkCredential]::new('', $secStrApiKey).Password)
}

# format the running process data and get unique entries
$sortedUniqueExes = Import-ExeCsvData $CsvFile

# load a copy of a local VT database if it exists
if($VirusTotalDB -or (Test-Path .\VTDB_*.json)) {
    if ($VirusTotalDB) {
        [System.Collections.ArrayList]$VTDB = Get-Content $VirusTotalDB | ConvertFrom-Json
    } else {
        [System.Collections.ArrayList]$VTDB = Get-Content .\VTDB_*.json | ConvertFrom-Json
    }
    Write-Output 'Local VirusTotal database was loaded.'

    $count = 0
    foreach ($exe in $sortedUniqueExes) {
        foreach ($entry in $VTDB) {
            # make sure the hash and image file path match
            if ($exe.Hash -eq $entry.Hash -and $exe.Path -eq $entry.Path) {
                $exe.Positives = $entry.Positives
                $exe.Total = $entry.Total
                $exe.ScanDate = $entry.ScanDate
                $exe.ScanResults = "$($entry.ScanResults)"
                $exe.Link = $entry.Link
                $count++
            }
        }
    }
    Write-Output "$count entries were found in the local VirusTotal database."

} else {
    Write-Output 'No local VirusTotal database. Generating a new one.'
}


# rate limit to $queries/min
$count = 0      # tracks VT request rate limit
$counter = 0    # tracks Write-Progress
$counter2 = 0

foreach ($entry in $sortedUniqueExes) {
    $activity        = "Get-VTReport ($($counter) of $($sortedUniqueExes.Length))"
    $currentStatus   = "Getting results for $($entry.Path)"
    $percentComplete = [int](($counter/$sortedUniqueExes.Length) * 100)
    Write-Progress -Activity $activity -Status $currentStatus -PercentComplete $percentComplete
    
    # query VT API using the image hash if there is no existing data for the current executable
    if ($entry.Total -eq $null) {
        $report = Get-VTReport -hash $entry.Hash

        if ($report.response_code -eq 1) {
            $entry.Positives = [int]$report.positives
            $entry.Total     = [int]$report.total
            $entry.ScanDate  = [datetime]$report.scan_date
            $entry.Link      = "$($report.permalink)"

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

            # add the new entry to the local VirusTotal database
            if ($VTDB) {
                $VTDB.Add($entry) | Out-Null
                $counter2++
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
        if (($count % $Queries) -eq 0) {
            Write-Progress -Activity $activity -Status $currentStatus -PercentComplete $percentComplete -CurrentOperation "Rate limit reached. Pausing."
            $count = 0
            Start-Sleep -Seconds 60
        }
    }

    $counter++
}

Write-Output "$counter2 entries were added to the local VirusTotal database."

# if an existing local VirusTotal database file was used, write the updated version to file
# otherwise create a new database file from the current hashed file set
if ($VTDB) {
    $VTDB | ConvertTo-Json | Out-File -FilePath "VTDB_$(Get-Date -Format FileDateUniversal).json"
    Write-Output 'Writing new updated VirusTotal database.'
} else {
    $sortedUniqueExes | ConvertTo-Json | Out-File -FilePath "VTDB_$(Get-Date -Format FileDateUniversal).json"
    Write-Output 'Writing new VirusTotal database.'
}

if (-not $DoNotExportCsvResults) {
    $sortedUniqueExes | Export-Csv "virus_total_results.csv" -NoTypeInformation
    Write-Output 'VirusTotal CSV results saved.'
}

Remove-VTApiKey