# Copyright 2023, 2024 HCL America
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

#During Job Cancellation, we want to also try to stop the scan if it was already initiated

#DEBUG
#dir env:
#$DebugPreference = "Continue"
$DebugPreference = "SilentlyContinue"

#INITIALIZE VARIABLES
$scanidFileName = ".\scanid.txt"
$ephemeralPresenceIdFileName =".\ephemeralPresenceId.txt"

$global:BaseAPIUrl = $env:INPUT_BASEURL + "/api/v4"

#LOAD ALL ASOC FUNCTIONS FROM LIBRARY FILE asoc.ps1
. "$env:GITHUB_ACTION_PATH/asoc.ps1"


$global:scanId = Get-Content $scanidFileName | Select -First 1
Write-Host "ScanID: $global:scanId"

Login-ASoC

Delete-LatestRunningScanExecution($global:scanId)

# kill the ephemeral presence if one was set
if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
    
    $global:ephemeralPresenceId = Get-Content $ephemeralPresenceIdFileName | Select -First 1
    Write-Host "Ephemeral Presence ID extracted from file: $global:ephemeralPresenceId"
    
    Write-Host "Deleting ephemeral presence with ID: $global:ephemeralPresenceId"
    Run-ASoC-DeletePresence($global:ephemeralPresenceId)
}