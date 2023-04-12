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
      Uri         = "$env:INPUT_BASEURL/Apps/GetAsPage"
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
    'fileToUpload' = Get-Item -Path $filepath
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

  $global:jsonBodyInPSObject.Add("LoginUser",$env:INPUT_LOGIN_USER)
  $global:jsonBodyInPSObject.Add("LoginPassword",$env:INPUT_LOGIN_PASSWORD)

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
  $global:jsonBodyInPSObject.Add("ScanFileId",$FileID)

  return Run-ASoC-DynamicAnalyzerWithFileAPI($jsonBodyInPSObject | ConvertTo-Json)
}


function Run-ASoC-DynamicAnalyzerAPI($json){

  write-host $json
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/DynamicAnalyzer"
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

function Run-ASoC-DynamicAnalyzerWithFileAPI($json){

  Write-Debug ($json | Format-Table | Out-String)
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/DynamicAnalyzerWithFile"
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
    Method      = 'Get'
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
    Method      = 'Post'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{
    'Configuration' = @{
      'Summary' = "true"
      'Details' = "true"
      'Discussion' = "true"
      'Overview' = "true"
      'TableOfContent' = "true"
      'Advisories' = "true"
      'FixRecommendation' = "true"
      'History' = "true"
      'Coverage' = "true"
      'MinimizeDetails' = "true"
      'Articles' = "true"
      'ReportFileType' = "HTML"
      'Title' = "$global:scan_name"
      'Locale' = "en-US"
      'Notes' = "Github SHA: $env:GITHUB_SHA"
      'Comments' = "true"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)
  Write-Debug ($body | Format-Table | Out-String)

  $output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-JSON)
  $report_ID = $output_runreport.Id
  return $report_ID
}

function Run-ASoC-ReportCompletionChecker($reportID){

  #Wait for report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/$reportID"
    Method      = 'Get'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $report_status ="Not Ready"
  while($report_status -ne "Ready"){
    $output = Invoke-RestMethod @params
    $report_status = $output.Status
    Start-Sleep -Seconds 5
    Write-Host "Generating Report... Progress: " $output.Progress "%"
  } 
}

function Run-ASoC-DownloadReport($eportID){

  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/Download/$eportID"
    Method      = 'Get'
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
    
  #/api/v2/Issues/CountBySeverity/{scope}/{scopeId}
  $params = @{
      Uri         = "$global:BaseAPIUrl/Issues/CountBySeverity/Scan/$scanID"+"?applyPolicies="+"$policyScope"
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

  return $jsonOutput

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
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"?applyPolicies=None&%24inlinecount=allpages"
    Method      = 'Get'
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

function Run-ASoC-SetCommentForIssue($issueId,$inputComment){
  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/$issueId"
    Method      = 'Put'
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
  return $jsonOutput
}

#DELETE
function Run-ASoC-SetBatchComments($scanId, $inputComment){
  

  #https://cloud.appscan.com/api/v2/Issues/Scan/9d989c39-70bf-ed11-ba76-14cb65723612?odataFilter=test&applyPolicies=None

  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$issueId"+"applyPolicies=None"
    Method      = 'Put'
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
    Uri         = "$global:BaseAPIUrl/Scans/$scanId"
    Method      = 'Get'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $jsonOutput = Invoke-RestMethod @params
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
    Method      = 'Post'
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
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId+"/DownloadV2?platform="+$platform
    Method      = 'Post'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $ProgressPreference = 'SilentlyContinue'
  $jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName
  $ProgressPreference = 'Continue'
  
  return $jsonOutput
}


function Run-ASoC-DeletePresence($presenceId){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId
    Method      = 'Delete'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  try {
    $response = Invoke-WebRequest @params
    Write-Host "Successfully deleted presence with ID: $presenceId"

    
  }
  catch {
      Write-Host "Failed to delete presence with ID: $presenceId"
  
  }
  
}


function Run-ASoC-GetPresenceIdGivenPresenceName($presenceName){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"
    Method      = 'Get'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $response = Invoke-RestMethod @params

  foreach($i in $response){
    if($i.PresenceName -eq $presenceName){
      return $i.Id
    }
  }
}

function Run-ASoC-CheckPresenceStatus($presenceId){

    #CREATE PRESENCE
    $params = @{
      Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId
      Method      = 'Get'
      Headers = @{
        Authorization = "Bearer $global:BearerToken"
        'Content-Type' = 'application/json'
      }
    }
    #DEBUG
    Write-Debug ($params | Format-Table | Out-String)
  
    $jsonOutput = Invoke-RestMethod @params
    
    if($jsonOutput.Status -eq 'Active'){
      Write-Host "AppScan Presence with ID: $presenceId is in active state. "
      return $true
    }else{
      Write-Host "AppScan Presence with ID:" $presenceId "is NOT yet in active state. State =" $jsonOutput.Status
      return $false
    }
}

#Creates a ephemeral presence. Returns the presenceId if successful.
function Create-EphemeralPresenceWithDocker{

  $presenceName = "Temp instance for Github Action"
  $presenceFileName = 'presence.zip'
  $presenceFolder = 'presence'
  $platform = 'linux_x64'

  #DELETE PRESENCE IF PRESENT
  $presenceId = Run-ASoC-GetPresenceIdGivenPresenceName($presenceName)
  Run-ASoC-DeletePresence($presenceId)

  #CREATE A NEW PRESENCE
  $presenceId = Run-ASoC-CreatePresence($presenceName)
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform


  $dockerContainerName = 'appscanpresence_container'
  $dockerImageName = 'appscanpresence_image'
  $dockerfileName = 'presence_dockerfile'

  #Start presence in a container
  if ((docker ps --format '{{.Names}}') -contains $dockerContainerName) {
    docker stop $dockerContainerName
    docker rm $dockerContainerName
  }
  
  docker build -f $env:GITHUB_ACTION_PATH/$dockerfileName -t $env:GITHUB_ACTION_PATH/$dockerImageName .
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
    Write-Error "Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  }
}


#Creates a ephemeral presence. Returns the presenceId if successful.
function Create-EphemeralPresence{

  $presenceName = "Temp instance for Github Action"
  $presenceFileName = 'presence.zip'
  $presenceFolder = 'presence'
  if($IsLinux){
    $platform = 'linux_x64'
  }elseif($IsWindow){
    $platform = 'win_x64'
  }else{
    Write-Error "The OS used is not supported by AppScan Presence. Please use a supported OS: https://help.hcltechsw.com/appscan/ASoC/Presence_Sysreq.html"
    exit 1
  }
  
  #DELETE PRESENCE IF PRESENT
  $presenceId = Run-ASoC-GetPresenceIdGivenPresenceName($presenceName)
  Run-ASoC-DeletePresence($presenceId)

  #ENSURE DIRECTORY IS CLEAN AND $presenceFolder FOLDER NAME and $presenceFileName ARE NOT PRESENT
  Remove-Item $presenceFileName -Recurse -ErrorAction SilentlyContinue
  Remove-Item $presenceFolder -Recurse -ErrorAction SilentlyContinue

  #CREATE A NEW PRESENCE
  $presenceId = Run-ASoC-CreatePresence($presenceName)
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform

  Expand-Archive -Path $presenceFileName -DestinationPath $presenceFolder

  #Start The Presence
  if($IsLinux){
    sudo chmod +x "$presenceFolder/startPresenceAsService.sh" | Out-String | Write-Output
    & sudo "$presenceFolder/startPresenceAsService.sh" start  | Out-String | Write-Output
  
  }elseif($IsWindow){
    & "$presenceFolder/startPresenceAsService.bat" create  | Out-String | Write-Output
    & "$presenceFolder/startPresenceAsService.bat" start | Out-String | Write-Output
  }else{
    Write-Error "The OS used in the runner is not supported by AppScan Presence. Please use a supported OS: https://help.hcltechsw.com/appscan/ASoC/Presence_Sysreq.html"
    exit 1
  }

  #Pause for 5 seconds for the commands to complete
  Start-Sleep -Seconds 5

  #Check if presence is up and running

  $i = 1
  $checkPresenceMaxCount = 5 #Number of times to check if Presence is up and running
  $pauseDuration = 5 #pause duration in seconds
  $presenceStatus = $false
  while(($i -le $checkPresenceMaxCount) -and ($presenceStatus -eq $false)){

    Write-Host "Checking for Presence Status..."
    $presenceStatus = Run-ASoC-CheckPresenceStatus($presenceId)
    Start-Sleep -Seconds $pauseDuration
    $i = $i + 1

  }

  if($presenceStatus){
      Write-Host "Ephemeral Presence is deployed and running"
      return $presenceId
  }else{
    Write-Error "Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  }
}

function Create-EphemeralPresenceTest{

  $presenceName = "Temp instance for Github Action"
  $presenceFileName = 'presence.zip'
  $presenceFolder = 'presence'
  <# if($IsLinux){
    $platform = 'linux_x64'
  }elseif($IsWindow){
    $platform = 'win_x64'
  }else{
    Write-Error "The OS used is not supported by AppScan Presence. Please use a supported OS: https://help.hcltechsw.com/appscan/ASoC/Presence_Sysreq.html"
    exit 1
  } #>
  
  #DELETE PRESENCE IF PRESENT
  $presenceId = Run-ASoC-GetPresenceIdGivenPresenceName($presenceName)
  Run-ASoC-DeletePresence($presenceId)

  #ENSURE DIRECTORY IS CLEAN AND $presenceFolder FOLDER NAME and $presenceFileName ARE NOT PRESENT
  Remove-Item $presenceFileName -Recurse -ErrorAction SilentlyContinue
  Remove-Item $presenceFolder -Recurse -ErrorAction SilentlyContinue

  #CREATE A NEW PRESENCE
  $presenceId = Run-ASoC-CreatePresence($presenceName)
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform

  Expand-Archive -Path $presenceFileName -DestinationPath $presenceFolder

  #Start The Presence
<#   if($IsLinux){
    sudo chmod +x "$presenceFolder/startPresenceAsService.sh"
    & sudo "$presenceFolder/startPresenceAsService.sh" start
  
  }elseif($IsWindow){
    & "$presenceFolder/startPresenceAsService.bat" create
    & "$presenceFolder/startPresenceAsService.bat" start
  }else{
    Write-Error "The OS used is not supported by AppScan Presence. Please use a supported OS: https://help.hcltechsw.com/appscan/ASoC/Presence_Sysreq.html"
    exit 1
  } #>

  #Check if presence is up and running

  $i = 1
  $checkPresenceMaxCount = 5 #Number of times to check if Presence is up and running
  $pauseDuration = 5 #pause duration in seconds
  $presenceStatus = $false
  while(($i -le $checkPresenceMaxCount) -and ($presenceStatus -eq $false)){

    Write-Host "Checking for Presence Status..."
    $presenceStatus = Run-ASoC-CheckPresenceStatus($presenceId)
    Start-Sleep -Seconds $pauseDuration
    $i = $i + 1

  }
  
  return $presenceId
  <# if($presenceStatus){
      Write-Host "Ephemeral Presence is deployed and running"
      return $presenceId
  }else{
    Write-Error "Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  } #>
}