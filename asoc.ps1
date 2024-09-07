# Copyright 2023 HCL America
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

Write-Host "Loading Library functions from asoc.ps1"
#FUNCTIONS
function Login-ASoC {

  $jsonBody = @{
    KeyId         = $env:INPUT_ASOC_KEY
    KeySecret     = $env:INPUT_ASOC_SECRET
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


  $Members = Invoke-RestMethod @params
  Write-Debug ($Members | Format-Table | Out-String)

  #Write-Host "Auth successful - Token received: $Members.token"
  $global:BearerToken = $Members.token

  if($global:BearerToken -ne ""){
    Write-Host "Login successful"
  }else{
    Write-Error "Login failed... exiting"
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
  $Members = Invoke-RestMethod @params
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
  $upload = Invoke-RestMethod @params
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
  
  $Members = Invoke-RestMethod @params
  return $Members.Id
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
    Uri         = "$global:BaseAPIUrl/Scans/$scanID/Executions"
    Method      = 'GET'
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

  while(($scan_status -ne "Ready") -and ($counterTimerInSeconds -lt $env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES*60)){
    $output = Invoke-RestMethod @params
    $scan_status = $output.Status
    Start-Sleep -Seconds $waitIntervalInSeconds
    $counterTimerInSeconds = $counterTimerInSeconds + $waitIntervalInSeconds
    Write-Host "." -NoNewline

    if($scan_status -eq 'Failed'){
      $error_message = $output.UserMessage
      $scanOverviewPage = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $global:scanId

      Write-Error "Scan status: $scan_status. Scan UserMessage: $error_message. For More detail, see Execution log available at your scan view: $scanOverviewPage"
      
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

  $output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json)
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
    $json = Invoke-RestMethod @params
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

  $output_runreport = Invoke-RestMethod @params
  Out-File -InputObject $output_runreport -FilePath ".\AppScan_Security_Report - $env:GITHUB_SHA.html"
  
}
#policies options are 'All' or 'None'
function Run-ASoC-GetIssueCount($scanID, $policyScope){

  #/api/v4/Issues/Scan/<scanID>?applyPolicies=all&$filter=status eq 'Open' or Status eq 'InProgress' or Status eq 'Reopened' or Status eq ‘New’ &$apply=groupby((Status,Severity),aggregate($count as N))
  $params = @{
      Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanID"+"?applyPolicies="+"$policyScope"+"&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27%20or%20Status%20eq%20%27New%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29"
      Method      = 'GET'
      Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
      }
  }
  
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $jsonOutput = Invoke-RestMethod @params

  #DEBUG
  #$jsonOutput

  return $jsonOutput.Items

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

  $jsonIssues = Invoke-RestMethod @params
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

  $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
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

  $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
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

  $response = Invoke-RestMethod @params
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

  $jsonOutput = Invoke-WebRequest @params
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

  $jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
  
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
  Write-Host "Inside DownloadPresence method"
  Write-Debug ($params | Format-Table | Out-String)

  $ProgressPreference = 'SilentlyContinue'
  $jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName
  Write-Host "Inside DownloadPresence method but after response"
  $ProgressPreference = 'Continue'
  
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

  $response = ""
  try {
    $response = Invoke-WebRequest @params
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

  $response = Invoke-RestMethod @params
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
      Uri         = "$global:BaseAPIUrl/Presences/"+"$filter=Id eq "+$presenceId
      Method      = 'GET'
      Headers = @{
        Authorization = "Bearer $global:BearerToken"
        'Content-Type' = 'application/json'
      }
    }
    #DEBUG
    Write-Debug ($params | Format-Table | Out-String)
  
    $response = Invoke-RestMethod @params
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
  Write-Host "$presenceId"
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform
  Write-Host $output
      Write-Host "Checkpoint-0"


  $dockerContainerName = 'appscanpresence_container'
  $dockerImageName = 'appscanpresence_image'
  $dockerfileName = 'dockerfile'

  #Start presence in a container
  if ((docker ps -a --format '{{.Names}}') -contains $dockerContainerName) {
    docker stop $dockerContainerName
    docker rm $dockerContainerName
    Write-Host "Checkpoint-1"
  }
  
      Write-Host "Checkpoint-2"
      Write-Host $env:GITHUB_ACTION_PATH/$dockerfileName
      Write-Host $dockerImageName
  docker buildx -f $env:GITHUB_ACTION_PATH/$dockerfileName -t $dockerImageName .
      Write-Host "Checkpoint-3"
  docker run --name $dockerContainerName -d $dockerImageName
      Write-Host "Checkpoint-4"

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
    Write-Error "Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  }
}
