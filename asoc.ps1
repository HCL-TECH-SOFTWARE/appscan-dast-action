# Copyright HCL Technologies Ltd. 2023, 2026.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$Os = 'linux'
if($IsMacOS){
  $Os = 'mac'
}elseif($IsWindows){
  $Os = 'win'
}

# Handle SSL validation
$global:SkipCert = $false
if ($env:INPUT_ACCEPTSSL -eq "true") {
  $global:SkipCert = $true
}

$version = 'v1.0.9'
if ($global:SkipCert) {
  $ClientType = "github-dast-$version"
} else {
  $ClientType = "github-dast-$Os-$version"
}

# =================================
# Base API URL
# =================================

$global:BaseAPIUrl = "$env:INPUT_BASEURL/api/v4"
Write-Host "Using AppScan Base API URL: $global:BaseAPIUrl"

Write-Host "Loading Library functions from asoc.ps1"

#FUNCTIONS
function Login-ASoC {

  $jsonBody = @{
    KeyId         = $env:INPUT_ASOC_KEY
    KeySecret     = $env:INPUT_ASOC_SECRET
    ClientType    = $ClientType
  }

  $params = @{
    Uri         = "$global:BaseAPIUrl/Account/ApiKeyLogin"
    Method      = 'POST'
    Body        = $jsonBody | ConvertTo-Json
    Headers = @{
      'Content-Type' = 'application/json'
      'accept' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($jsonBody | Format-Table | Out-String)
  Write-Debug ($params | Format-Table | Out-String)


  try {
    if ($global:SkipCert) {
      $Members = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $Members = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while logging in to AppScan."
    Exit 1
  }
  Write-Debug ($Members | Format-Table | Out-String)

  #Write-Host "Auth successful - Token received: $Members.token"
  $global:BearerToken = $Members.token

  if($global:BearerToken -ne ""){
    Write-Host "Login successful"
  }else{
    Write-Host "::error::Login failed... exiting"
    exit 1
  }

}

function Set-AppScanPresence{

  if($env:INPUT_NETWORK -eq 'private'){

    $global:jsonBodyInPSObject.Add("PresenceId",$env:INPUT_PRESENCE_ID)
    <#
    $global:jsonBodyInPSObject =+ @{
      PresenceId = $env:INPUT_PRESENCE_ID
    } #>
  }
}

function Lookup-ASoC-Application ($ApplicationName) {

  $params = @{
    Uri         = "$env:INPUT_BASEURL/Apps"
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  try {
    if ($global:SkipCert) {
      $Members = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $Members = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while looking up the AppScan application."
    Exit 1
  }
  Write-Host @Members
  $Members.Items.Contains($ApplicationName)
}


function Run-ASoC-FileUpload($filepath){

  #ls -l
  $uploadedFile = [IO.File]::ReadAllBytes($filepath)
  $params = @{
    Uri         = "$global:BaseAPIUrl/FileUpload"
    Method      = 'Post'
    Headers = @{
      'Content-Type' = 'multipart/form-data'
      Authorization = "Bearer $global:BearerToken"
    }
    Form = @{
      'uploadedFile' = Get-Item -Path $filepath
    }
  }
  try {
    if ($global:SkipCert) {
      $upload = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $upload = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while uploading the file to AppScan."
    Exit 1
  }
  $upload_File_ID = $upload.FileId
  write-host "File Uploaded - File ID: $upload_File_ID"

  return $upload_File_ID
}
function Run-ASoC-DynamicAnalyzerNoAuth {
  Write-Host "Proceeding with no authentications..." -ForegroundColor Green

  return Run-ASoC-DynamicAnalyzerAPI($global:jsonBodyInPSObject | ConvertTo-Json)
}
function Run-ASoC-DynamicAnalyzerUserPass{
  Write-Host "Proceeding with username and password login..." -ForegroundColor Green

  $Login = @{
    'Username' = $env:INPUT_LOGIN_USER
    'Password' = $env:INPUT_LOGIN_PASSWORD
  }
  $global:jsonBodyInPSObject.ScanConfiguration.Add('Login', $Login)

  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}

function Run-ASoC-DynamicAnalyzerRecordedLogin{

  Write-Host "Proceeding with recorded Login..." -ForegroundColor Green
  #Upload Recorded Login File
  $FileID = Run-ASoC-FileUpload($env:INPUT_LOGIN_SEQUENCE_FILE)
  $global:jsonBodyInPSObject.Add("LoginSequenceFileId",$FileID)
  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}


function Run-ASoC-DynamicAnalyzerWithFile{

  $FileID = Run-ASoC-FileUpload($env:INPUT_SCAN_OR_SCANT_FILE)
  $global:jsonBodyInPSObject.Remove('ScanConfiguration')
  $global:jsonBodyInPSObject.Add("ScanOrTemplateFileId",$FileID)

  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}

function Run-ASoC-DynamicAnalyzerAPI($json){

  write-host $json
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/Dast"
    Method      = 'POST'
    Body        = $json
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }

  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$Members = Invoke-RestMethod @params
  try {
    if ($global:SkipCert) {
      $Members = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    }
    else {
      $Members = Invoke-RestMethod @params -ErrorAction Stop
    }
    return $Members.Id
  }
  catch {
    $responseBody = $_.ErrorDetails.Message

    if ($responseBody) {
      try {
        $errorJson = $responseBody | ConvertFrom-Json
        if ($errorJson.Message) {
          $errorMessage = $errorJson.Message
          if ($errorJson.FormatParams) {
            for ($i = 0; $i -lt $errorJson.FormatParams.Count; $i++) {
              $errorMessage = $errorMessage.Replace("{$i}", [string]$errorJson.FormatParams[$i])
            }
          }
          Write-Host $errorMessage -ForegroundColor Red
        } else {
          Write-Host "Error fetching response body for scan." -ForegroundColor Red
        }
      }
      catch {
        Write-Host "Error submitting scan to the analysis service. " -ForegroundColor Red
      }
    } else {
      Write-Host "Error creating scan." -ForegroundColor Red
    }
    Write-Host "::error::Scan creation Failed."
    Exit 1
  }
}

function Run-ASoC-DAST{

  #FIRST check if dynamic_scan_type is 'upload' or 'dast'
  if($env:INPUT_DYNAMIC_SCAN_TYPE -eq 'upload'){
    return Run-ASoC-DynamicAnalyzerWithFile

    #If dynamic_scan_type is not 'upload' then it is a regular 'dast' scan. We proceed to check if it's a userpass login or recorded login
  }elseif($env:INPUT_LOGIN_METHOD -eq 'userpass'){
    return Run-ASoC-DynamicAnalyzerUserPass

  }elseif($env:INPUT_LOGIN_METHOD -eq 'recorded'){
    return Run-ASoC-DynamicAnalyzerRecordedLogin

  }else{
    return Run-ASoC-DynamicAnalyzerNoAuth
  }
}

function Run-ASoC-ScanCompletionChecker($scanID){
  $params = @{
    Uri = "$global:BaseAPIUrl/Scans/$scanID/Executions"
    Method = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $counterTimerInSeconds = 0
  Write-Host "Waiting for Scan Completion..." -NoNewLine
  $waitIntervalInSeconds = 15

  while (($scan_status -ne "Ready") -and ($counterTimerInSeconds -lt [int]$env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES * 60)) {
    #$output = Invoke-RestMethod @params
    try {
      if ($global:SkipCert) {
        $output = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
      } else {
        $output = Invoke-RestMethod @params -ErrorAction Stop
      }
    } catch {
      Write-Host "" # Breaks the dot-printing line cleanly

      $responseBody = $_.ErrorDetails.Message
      $apiErrorMsg = ""

      # Attempt to cleanly parse the backend JSON error
      if ($responseBody) {
        try {
          $errorJson = $responseBody | ConvertFrom-Json
          if ($errorJson.Message) {
            $apiErrorMsg = $errorJson.Message
            if ($errorJson.FormatParams) {
              for ($i = 0; $i -lt $errorJson.FormatParams.Count; $i++) {
                $apiErrorMsg = $apiErrorMsg.Replace("{$i}", [string]$errorJson.FormatParams[$i])
              }
            }
          }
        }
        catch {
          # Ignore parsing errors, $apiErrorMsg remains empty
        }
      }

      if ($apiErrorMsg) {
        Write-Host "::error::Scan completion check failed. Response: $apiErrorMsg"
      }
      else {
        Write-Host "::error::Scan completion check failed."
      }
      Exit 1
    }

    $scan_status = $output.Status
    Start-Sleep -Seconds $waitIntervalInSeconds
    $counterTimerInSeconds = $counterTimerInSeconds + $waitIntervalInSeconds
    Write-Host "." -NoNewline

    if ($scan_status -eq 'Failed') {
      $error_message = if (-not [string]::IsNullOrWhiteSpace($output.UserMessage)) { $output.UserMessage } else { $output.ErrorMessage }
      $scanOverviewPage = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $global:scanId
      Write-Host "::error::Scan status: $scan_status. Scan Message: $error_message. For More detail, see Execution log available at your scan view: $scanOverviewPage"
      Exit 1
    }
  }
  Write-Host ""
}

function Run-ASoC-GenerateReport ($scanID) {

  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/Security/Scan/$scanID"
    Method      = 'POST'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{
    'Configuration' = @{
      'Summary' = $true
      'Details' = $true
      'Discussion' = $true
      'Overview' = $true
      'TableOfContent' = $true
      'Advisories' = $true
      'FixRecommendation' = $true
      'History' = $true
      'Coverage' = $true
      'MinimizeDetails' = $true
      'Articles' = $true
      'ReportFileType' = "HTML"
      'Title' = "$global:scan_name"
      'Locale' = "en-US"
      'Notes' = "Github SHA: $env:GITHUB_SHA"
      'Comments' = $true
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)
  Write-Debug ($body | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $output_runreport = Invoke-RestMethod @params -Body ($body | ConvertTo-Json) -SkipCertificateCheck -ErrorAction Stop
    } else {
      $output_runreport = Invoke-RestMethod @params -Body ($body | ConvertTo-Json) -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while generating the report."
    Exit 1
  }
  $report_ID = $output_runreport.Id
  return $report_ID
}

function Run-ASoC-ReportCompletionChecker($reportID){

  #Wait for report
  #/api/v4/Reports $filter= Id eq <ReportId>
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports" + "?%24filter=Id%20eq%20" + $reportID
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $report_status ="Not Ready"
  while($report_status -ne "Ready"){
    #$json = Invoke-RestMethod @params
    try {
      if ($global:SkipCert) {
        $json = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
      } else {
        $json = Invoke-RestMethod @params -ErrorAction Stop
      }
    } catch {
      Write-Host "::error::An error occurred while checking report completion."
      Exit 1
    }
    $output = $json.Items[0]
    $report_status = $output.Status
    Start-Sleep -Seconds 5
    Write-Host "Generating Report... Progress: " $output.Progress "%"
  }
}

function Run-ASoC-DownloadReport($reportID){

  #Download Report
  #/api/v4/Reports/{ReportId}/Download
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/$reportID/Download"
    Method      = 'GET'
    Headers = @{
      'Accept' = 'text/html'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $output_runreport = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $output_runreport = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while downloading the report."
    Exit 1
  }
  Out-File -InputObject $output_runreport -FilePath ".\AppScan_Security_Report - $env:GITHUB_SHA.html"

}
#policies options are 'All' or 'None'
function Run-ASoC-GetIssueCount($scanID, $policyScope){

  #/api/v4/Issues/Scan/<scanID>?applyPolicies=all&$filter=status eq 'Open' or Status eq 'InProgress' or Status eq 'Reopened' &$apply=groupby((Status,Severity),aggregate($count as N))
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanID"+"?applyPolicies="+"$policyScope"+"&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29"
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }

  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    #$jsonOutput = Invoke-RestMethod @params
    if ($global:SkipCert) {
      $jsonOutput = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-RestMethod @params -ErrorAction Stop
    }
    return $jsonOutput.Items
  } catch {
    Write-Host "::error::An error occurred while fetching issue count."
    Exit 1
  }

}

function FailBuild-ByNonCompliance($issueCountJson){

  $failBuild = $false
  $totalIssues = 0
  foreach($i in $issueCountJson){
    $totalIssues = $totalIssues + $i.Count
  }

  #DEBUG
  Write-Host "Total issues: $totalIssues"
  if($totalIssues -gt 0){
    $failBuild = $true
  }
  return $failBuild
}


function FailBuild-BySeverity($issueCountJson, $failureThresholdText){

  #0 = Informational
  #1 = Low
  #2 = Medium
  #3 = High
  #4 = Critical
  $failureThresholdNum = 0
  $failureThresholdNum = Get-SeverityValue($failureThresholdText)
  $totalIssuesCountAboveThreshold = 0
  $failBuild = $false

  foreach($i in $issueCountJson){
    $sevNum = Get-SeverityValue($i.Severity)
    if($sevNum -ge $failureThresholdNum){
      $totalIssuesCountAboveThreshold = $totalIssuesCountAboveThreshold + $i.Count
    }
  }

  #DEBUG
  Write-Host "Total count of issues above threshold: $totalIssuesCountAboveThreshold"

  if($totalIssuesCountAboveThreshold -gt 0){
    $failBuild = $true
  }
  return $failBuild
}


function Get-SeverityValue($severityText){

  $severityValue = 1;

  switch($severityText){
    'Informational' {$severityValue = 0;break}
    'Low'           {$severityValue = 1;break}
    'Medium'        {$severityValue = 2;break}
    'High'          {$severityValue = 3;break}
    'Critical'      {$severityValue = 4;break}
  }
  return $severityValue

}

function Run-ASoC-GetAllIssuesFromScan($scanId){

  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"?applyPolicies=None"
    Method      = 'GET'
    Headers = @{
      'Accept' = 'text/html'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $jsonIssues = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonIssues = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while fetching issues from the scan."
    Exit 1
  }
  return $jsonIssues
}

function Run-ASoC-SetCommentForIssue($scanId, $issueId, $inputComment){
  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"?odataFilter=Id%20eq%20"+$issueId
    Method      = 'PUT'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    Comment = $inputComment
  }
  #DEBUG
  #Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while setting the issue comment."
    Exit 1
  }
  return "Done"
}

#DELETE
function Run-ASoC-SetBatchComments($scanId, $inputComment){


  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"applyPolicies=None"
    Method      = 'PUT'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    Comment = $inputComment
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while setting batch issue comments."
    Exit 1
  }
  return $jsonOutput
}
function Run-ASoC-GetScanDetails($scanId){

  #$latestScanExecutionId = ''

  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/"+"?%24filter=Id%20eq%20"+$scanId
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $response = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $response = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while fetching scan details."
    Exit 1
  }
  $array = $response.Items
  $jsonOutput = $array[0]
  #$latestScanExecutionId = $jsonOutput.LatestExecution.Id
  return $jsonOutput

}


function Run-ASoC-CancelScanExecution($executionId){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/Execution/$executionId/"
    Method      = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $jsonOutput = Invoke-WebRequest @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-WebRequest @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while cancelling the scan execution."
    Exit 1
  }
  Write-Debug $jsonOutput
  return $jsonOutput
}

function Delete-LatestRunningScanExecution($scanId){

  $ExecutionId = ''
  $ExecutionProgress = ''

  $scanDetailJson = Run-ASoC-GetScanDetails($scanId)

  $ExecutionId = $scanDetailJson.LatestExecution.Id
  $ExecutionProgress = $scanDetailJson.LatestExecution.ExecutionProgress

  if($ExecutionProgress -ne 'Completed'){

    $cancelStatus = Run-ASoC-CancelScanExecution($ExecutionId)
    Write-Debug $cancelStatus

    if($cancelStatus.StatusCode -In 200..299){
      Write-Host "Latest Scan Execution with Execution ID: $ExecutionId is successfully cancelled."
    }else{
      Write-Host "Cancellation of Scan with Execution ID: $executionId unsuccessful. See debug output:"
      Write-Host $cancelStatus
    }

  }else{
    Write-Host "Latest scan execution ID: $ExecutionId is already completed and not occupying a scan queue."
  }
}

#Epheremal presence related functions
function Run-ASoC-CreatePresence($presenceName){

  #CREATE PRESENCE
  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences"
    Method      = 'POST'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    PresenceName = $presenceName
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody | ConvertTo-JSON) -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while creating the AppScan presence."
    Exit 1
  }

  $presenceId = $jsonOutput.Id
  return $presenceId


}

function Run-ASoC-DownloadPresence($presenceId, $OutputFileName, $platform){

  #DOWNLOAD PRESENCE ZIP FILE
  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId+"/Download/"+$platform
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $ProgressPreference = 'SilentlyContinue'
  #$jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName
  try {
    if ($global:SkipCert) {
      $jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName -SkipCertificateCheck -ErrorAction Stop
    } else {
      $jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while downloading the AppScan presence."
    Exit 1
  } finally {
    $ProgressPreference = 'Continue'
  }

  return $jsonOutput
}


function Run-ASoC-DeletePresence($presenceId){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId
    Method      = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    #$response = Invoke-WebRequest @params
    if ($global:SkipCert) {
      $response = Invoke-WebRequest @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $response = Invoke-WebRequest @params -ErrorAction Stop
    }
    Write-Host "Successfully deleted presence with ID: $presenceId"
  }
  catch {
    Write-Host "Failed to delete presence with ID: $presenceId"
    Write-Host "The request failed with error: $($_.Exception.Message)"
    Write-Host "The request failed with HTTP status code $($response.StatusCode)"
    Write-Host "The failure message is: $($response.StatusDescription)"
  }

}


function Run-ASoC-GetPresenceIdGivenPresenceName($presenceName){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences"
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $response = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $response = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while fetching AppScan presences."
    Exit 1
  }
  $array = $response.Items

  foreach($i in $array){
    if($i.PresenceName -eq $presenceName){
      return $i.Id
    }
  }
}

function Run-ASoC-CheckPresenceStatus($presenceId){

  #CREATE PRESENCE
  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences?%24filter=Id%20eq%20"+$presenceId
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    if ($global:SkipCert) {
      $response = Invoke-RestMethod @params -SkipCertificateCheck -ErrorAction Stop
    } else {
      $response = Invoke-RestMethod @params -ErrorAction Stop
    }
  } catch {
    Write-Host "::error::An error occurred while checking AppScan presence status."
    Exit 1
  }
  $array = $response.Items
  $jsonOutput = $array[0]

  if($jsonOutput.Status -eq 'Active'){
    Write-Host "AppScan Presence with ID: $presenceId is in active state. "
    return $true
  }else{
    Write-Host "AppScan Presence with ID:" $presenceId "is NOT yet in active state. State =" $array.Status
    return $false
  }
}

#Creates a ephemeral presence. Returns the presenceId if successful.
function Create-EphemeralPresenceWithDocker{

  #$global:ephemeralPresenceName = "Github $env:GITHUB_SHA"
  $presenceName = $global:ephemeralPresenceName
  $presenceFileName = 'presence.zip'
  $presenceFolder = 'presence'
  $platform = 'linux_x64'

  #DELETE PRESENCE IF PRESENT
  $presenceId = Run-ASoC-GetPresenceIdGivenPresenceName($presenceName)
  if($presenceId){
    Run-ASoC-DeletePresence($presenceId)
  }


  #CREATE A NEW PRESENCE
  $presenceId = Run-ASoC-CreatePresence($presenceName)
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform

  $dockerContainerName = 'appscanpresence_container'
  $dockerImageName = 'appscanpresence_image'
  $dockerfileName = 'dockerfile'

  #Start presence in a container
  if ((docker ps -a --format '{{.Names}}') -contains $dockerContainerName) {
    docker stop $dockerContainerName
    docker rm $dockerContainerName
  }

  Write-Host "Creating docker image..."
  (docker build -f $env:GITHUB_ACTION_PATH/$dockerfileName -t $dockerImageName .) 2>&1

  Write-Host "Starting container..."
  docker run --name $dockerContainerName -d $dockerImageName

  #Pause for 5 seconds for the commands to complete
  Start-Sleep -Seconds 5

  #Get latest docker log
  Write-Host "Getting Latest Appscan Presence Log from the container:"
  docker logs $dockerContainerName

  #Check if presence is up and running

  $i = 1
  $checkPresenceMaxCount = 5 #Number of times to check if Presence is up and running
  $pauseDuration = 5 #pause duration in seconds
  $presenceStatus = $false
  while(($i -le $checkPresenceMaxCount) -and ($presenceStatus -eq $false)){

    Write-Host "Checking for Presence Status from ASoC..."
    $presenceStatus = Run-ASoC-CheckPresenceStatus($presenceId)
    Start-Sleep -Seconds $pauseDuration
    $i = $i + 1

  }

  if($presenceStatus){
    Write-Host "Ephemeral Presence is deployed and running"
    $global:ephemeralPresenceId = $presenceId
  }else{
    Write-Host "::error::Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  }
}

