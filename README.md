# Get-VirusTotalResults
This PowerShell cmdlet allows you to batch submit process hashes via the VirusTotal (VT) API.  It incorporates @DBHeise [VirusTotal.psm1](https://github.com/DBHeise/Powershell/blob/master/Modules/VirusTotal/VirusTotal.psm1) for VirusTotal API interaction.  The code uses as input the `processes.csv` output from the [Collect-ADDomainData.ps1](https://github.com/bishoppebbles/Collect-ADDomainData) (i.e., FakeHyena) script.

This script prompts the user for their VirusTotal API key.  It then imports a CSV file produced from the [Collect-ADDomainData.ps1](https://github.com/bishoppebbles/Collect-ADDomainData) script that includes process name, path, and hash information.  `Get-VirusTotalResults` is processed to create unique entries based on the process's path and hash (i.e., if the hash is the same but it was located in a different path there would be two separate entries).  If there is no local json database file, all process file hashes are submitted to VT for analysis.  Note that only hashes are submitted, no file data.  The results are written to a CSV with the following fields: `Name`, `Path`, `Hash`, `Positives`, `Total`, `ScanDate`, `ScanResults` (A/V scan engine(s) with positive results), `Link` (VT results link).  A local json database file is also written for optional later reuse.  If a local json database exists from a previous scan, the current process hash data is first compared against this database for any matching results.  Then only the remaining entries are submitted to VT for review.  A new, updated json database file with the total cumulative results are then written to disk for later optional reuse.

By default the VT API submission rate is limited to 1000 API submissions before the code will sleep for 60 seconds.  This is effectively no rate limit as it's unlikely 1000 submissions will be required in a mostly homogenous computing enterprise environment, at least based on my tests (i.e., there are not going to be that many unique running processes).  However, if you have a small VT API submission rate (e.g., 4/minute) this can be used to slowly submit your process hash data.  This feature hasn't been thoroughly tested.  

### Options
* `CsvFile`
  * The CSV file to import containing the process name, path, and hash information.
* `VirusTotalDB`
  * The CSV file to import containing the process name, path, and hash information.
* `Queries`
  * Rate limit for the number of VirusTotal API queries per minutes (default = 1000).
* `DoNotExportCsvResults`
  * Switch parameter to skip writing the CSV results to file.  This would only write a new json database file of the new VT analysis.
* `ForceClearApiKey`
  * Clear an existing API key entry so a new one can be entered.

### Examples
`.\Get-VirusTotalResults.ps1 -CsvFile .\processes.csv`

* Submits the process hash data taken from the `Collect-ADDomainData.ps1` (i.e., FakeHyena) script.  By default it will look for a local JSON VT database file in the current working directory for previous VT queries and use any existing matches from that.  If not present, all values are submited to VT.  An updated new VT JSON database file is written to disk.

`.\Get-VirusTotalResults.ps1 -CsvFile .\process.csv -Queries 4`

* Same as the above but rate limits the VT API queries to 4 with a 60 second sleep.  The default is set to 1000 VT API queries before a 60 second sleep.

`.\Get-VirusTotalResults.ps1 -CsvFile .\processes.csv -VirusTotalDB ..\vtdb\VTDB_20240209Z.json`

* Submits the process hash data taken from the `Collect-ADDomainData.ps1` (i.e., FakeHyena) script.  Looks in a non-default location for an existing JSON VT database file for previous VT queries and use any existing matches from that.  An updated new VT JSON database file is written to disk.
