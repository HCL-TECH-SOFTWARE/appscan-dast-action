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

Write-Host "Starting ASoC script"

#DEBUG - To show DEBUG Messages, set $DebugPreference = 'Continue'


#$DebugPreference = 'Continue'
$DebugPreference = 'SilentlyContinue'

Write-Debug "Print environment variables:"
Write-Host "github.sha: " $env:GITHUB_SHA
ls -l
dir env:

#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#INITIALIZING VARIABLES
$global:BearerToken = ""
$global:scan_name = ''
if([string]::IsNullOrEmpty($env:INPUT_SCAN_NAME)){
  $global:scan_name = "$env:GITHUB_REPOSITORY $env:GITHUB_SHA"
}else{
  $global:scan_name = "$env:INPUT_SCAN_NAME"
}
$global:jsonBodyInPSObject = ""
$global:scanId = ""
$env:scanId = ""
$global:BaseAPIUrl = ""
$global:BaseAPIUrl = $env:INPUT_BASEURL + "/api/v4"
Write-Debug $global:BaseAPIUrl
$global:ephemeralPresenceId = ""
$global:GithubRunURL = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
Write-Host "Gitub Run URL: $global:GithubRunURL"
$scanidFileName = ".\scanid.txt"
$ephemeralPresenceIdFileName =".\ephemeralPresenceId.txt"
$global:ephemeralPresenceName = "Github Runner $env:RUNNER_TRACKING_ID"

#${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}

#INITIALIZE
#Construct base JSON Body for DAST Scan for API DynamicAnalyzer and DynamicAnalyzerWithFiles
$global:jsonBodyInPSObject = @{
  ScanType = $env:INPUT_SCAN_TYPE
  IncludeVerifiedDomains = $true
  #ScanConfiguration = $global:ScanConfigurationJSON
  ScanConfiguration = {
    "Target" = @{
      "StartingUrl" = $env:INPUT_STARTING_URL
    }

    "Tests" = @{
      "TestOptimizationLevel" = $env:INPUT_OPTIMIZATION
    }
  }
  UseAutomaticTimeout = $true
  MaxRequestsIn = 10
  MaxRequestsTimeFrame = 1000
  OnlyFullResults = $true
  FullyAutomatic = $true
  ScanName = $global:scan_name
  #EnableMailNotification = $env:INPUT_EMAIL_NOTIFICATION
  Locale = 'en-US'
  AppId = $env:INPUT_APPLICATION_ID
  Execute = $true
  #Personal = $env:INPUT_PERSONAL_SCAN
  Target = $global.TargetJSON
  Login = $global.LoginJSON
  Tests = $global.TestsJSON
}

$global:ScanConfigurationJSON = @{
  Target = $global.TargetJSON
  Login = $global.LoginJSON
  Tests = $global.TestsJSON
}

$global:TargetJSON = @{
  StartingUrl = $env:INPUT_STARTING_URL
}

$global:LoginJSON = @{
}

$global:TestsJSON = @{
  TestOptimizationLevel = $env:INPUT_OPTIMIZATION
}

#LOAD ALL ASOC FUNCTIONS FROM LIBRARY FILE asoc.ps1
. "$env:GITHUB_ACTION_PATH/asoc.ps1"
#MAIN
Login-ASoC

#if ephemeral_presence is set to true, we will proceed to set our own presence settings and ignore other presence related settings on the YAML
if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
  
  Create-EphemeralPresenceWithDocker
  Write-Debug "Ephemeral Presence Id: $global:ephemeralPresenceId"
  $global:jsonBodyInPSObject.Add("PresenceId",$global:ephemeralPresenceId)

  #Save ephemeralPresence ID in a file
  $global:ephemeralPresenceId | Out-File -FilePath $ephemeralPresenceIdFileName -Force


}else{
  #CHECK NETWORK setting, if private, then set presence ID to the one on the YAML config
  Set-AppScanPresence
}

#Run DAST Scan
$global:scanId = Run-ASoC-DAST

#Save Scan ID in a file
$global:scanId | Out-File -FilePath $scanidFileName -Force

#Display ASoC Scan URL
$scanOverviewPage = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $global:scanId
Write-Host "Scan is initiated and can be viewed in ASoC Scan Dashboard:" 
Write-Host $scanOverviewPage -ForegroundColor Green

#IF ephemeral Presence is set, we must force set wait_for_analysis to true regardless of what the user has set. 
if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
  Write-Host "Since ephemeral_presence is true, wait_for_analysis will be set to true even if it was not set by user. This is required to keep the runner active and therefore keeps the ephemeral presence alive. "
  $env:INPUT_WAIT_FOR_ANALYSIS = $true
}

#If wait_for_analysis is set to true, we proceed to wait for scan completion, then performs report generation
if($env:INPUT_WAIT_FOR_ANALYSIS -eq $true){

  #Check for scan completion. The process pauses until scan is complete or timeout value has reached
  Run-ASoC-ScanCompletionChecker ($global:scanId)

  #As soon as the scan is complete, we kill the ephemeral presence if one was set
  if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
    Write-Host "Deleting ephemeral presence with ID: $global:ephemeralPresenceId"
    Run-ASoC-DeletePresence($global:ephemeralPresenceId)
  }

  #Update comment on ASoC issues
  $issueJson = Run-ASoC-GetAllIssuesFromScan($global:scanId)
  $issueItems = $issueJson.Items
  foreach($i in $issueItems){
    $issueId = $i.Id
    Write-Host "Writing Comments for Issue ID: $issueId"
    Run-ASoC-SetCommentForIssue $issueId "Issue found during Scan from Github SHA: $env:GITHUB_SHA, URL: $global:GithubRunURL"
  }

  #Send for report generation
  $reportID = Run-ASoC-GenerateReport ($global:scanId)
  
  #Check for report generation completion
  Run-ASoC-ReportCompletionChecker ($reportID)

  #Download report from ASoC
  Run-ASoC-DownloadReport($reportID)
  
  #issues found in scan
  $jsonData = Run-ASoC-GetIssueCount $global:scanId 'None'

  #This prints the number of issues by Severity
  $env:ISSUE_COUNT_BY_SEV = $jsonData | Format-Table | Out-String
  Write-Host $env:ISSUE_COUNT_BY_SEV


  #Fail the build if fail_for_noncompliance is set to true and if scan result count exceeds the threshold set in fail_threshold
  if($env:INPUT_FAIL_FOR_NONCOMPLIANCE -eq $true){

    $jsonData = Run-ASoC-GetIssueCount $global:scanId 'All'
    #$jsonData
    
    $failBuild = $false
    $failBuild = FailBuild-ByNonCompliance($jsonData)
    if($failBuild -eq $true){
        Write-Error "Job failed - Scan has determined non-compliance with the application policy set in ASoC."
        exit 1
    }
    else{
        Write-Host "Job Successful - Scan has determined compliance with policy current application policies set in ASoC." -ForegroundColor Green
    }
  }

  #Fail the build if fail_by_severity is true and scan results in non-compliance
  if($env:INPUT_FAIL_BY_SEVERITY -eq $true){
    $jsonData = Run-ASoC-GetIssueCount $global:scanId 'None'
    #$jsonData
    $failBuild = $false
    $failBuild = FailBuild-BySeverity $jsonData $env:INPUT_FAILURE_THRESHOLD
    Write-Debug "failbuild value is $failBuild"

    if($failBuild -eq $true){
        Write-Error "Job failed - Scan has found security issues equal to or above the threshold set: $env:INPUT_FAILURE_THRESHOLD"
        exit 1
    }
    else{
        Write-Host "Job Successful - Scan has found no issues equal to or above the threshold set: $env:INPUT_FAILURE_THRESHOLD." -ForegroundColor Green
    }
  }
}else{
  write-host "Since wait_for_analysis is set to false, the job is now complete. Exiting..."
  Exit 0
}
