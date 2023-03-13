# HCL AppScan DAST Github Action
Your code is better and more secure with HCL AppScan.

The HCL AppScan DAST Github Action enables you to run dynamic analysis security testing (DAST) against your application. The DAST scan identifies security vulnerabilities in your code and stores the results in AppScan on Cloud.

# Usage
## Register
If you don't have an account, register on [HCL AppScan on Cloud (ASoC)](https://cloud.appscan.com/) to generate your API key and API secret.

## Setup
1. Generate your API key and API secret on [the API page](https://cloud.appscan.com/main/apikey).
- The API key and API secret map to the `asoc_key` and `asoc_secret` parameters for this action. Store the API key and API secret as [secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets) in your repository.
![adingkeys_animation](img/keyAndSecret.gif)
2. Create the application in ASoC. 
- The application ID in ASoC maps to application_id for this action.

# Required Inputs
| Name |   Description    |
|    :---:    |    :---:    |
| asoc_key | Your API key from [the API page](https://cloud.appscan.com/main/apikey) |
| asoc_secret | Your API secret from [the API page](https://cloud.appscan.com/main/apikey) |
| application_id | The ID of the application in ASoC. |

# Optional Inputs
| Name | Description | Default Value | Available options |
|    :---:    |    :---:    |    :---:    |    :---:    |
| scan_name | The name of the scan created in ASoC. | The GitHub repository name + GITHUB SHA |  |
| scan_type | The type of the scan | staging | staging, production |
| dynamic_scan_type | Choose between dast or upload. DAST will require you to specify starting URL and login, while upload will only require you to specify a .scan or .scant file | dast | dast, upload |
| scan_or_scant_file |(applicable only if **dynamic_scan_type** = upload) Provide the path to the .scan or .scant file here| |  |
| starting_URL|(applicable only if **dynamic_scan_type** = dast)The starting URL of the DAST scan|https://demo.testfire.net?mode=demo ||
|optimization|Level of test optimization|Fast|NoOptimization, Fast, Faster, Fastest|
|network|Set the type of network, if this is set to private, you must have AppScan Presence created in advance|public|public, private|
|presence_id|(applicable only if network = private)|||
|login_method|(applicable only if **dynamic_scan_type** = dast)Login Method of the scan, none: no authentication required for the application, userpass: basic username/password authentication, recorded: you will provide a recorded login sequence dast.config file |none|none, userpass, or recorded|
|login_user|(applicable only if **login_method** = userpass) Type the username used for logging into the application|||
|login_password|(applicable only if **login_method** = userpass) Type the password used logging into the application|||
|login_sequence_file|Provide a path to the Login Traffic File data. Supported file type: DAST.CONFIG: AppScan Activity Recorder file|||
|email_notification|Send email notification uponn scan completion|false|true,false|
| personal_scan | Make this a [personal scan](https://help.hcltechsw.com/appscan/ASoC/appseccloud_scans_personal.html). | false | true, false|
|wait_for_analysis|If set to true, the job will suspend and wait until DAST scan is complete before finishing the job| true| true, false|
|wait_for_analysis_timeout_minutes|(applicable only if **wait_for_analysis** = true) Maximum duration in minutes before the job will no longer wait and proceeds to complete, default is 360 (6 hours)|360||
|fail_for_noncompliance|If **fail_for_noncompliance** is true, fail the job if any non-compliant issues are found in the scan|false|true, false|
|fail_by_severity|If **fail_by_severity** is set to true, failure_threshold must also be set. This will fail the job if any issues equal to or higher (more severe) than **failure_threshold** are found in the scan|false|false|
|failure_threshold|(applicable only if **failure_threshold** = true) Set the severity level that indicates a failure. Lesser severities will not be considered a failure. For example, if **failure_threshold** is set to Medium, Informational and/or Low severity issues will not cause a failure. Medium, High, and/or Critical issues will cause a failure.|High|Informational, Low, Medium, High, Critical|

# Example 1 - DAST scan with basic username and password login method, using the public network
```yaml
name: "HCL AppScan DAST"
on:
  workflow_dispatch
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      - name: Run ASoC DAST Scan
        uses: antonychiu2/asoc-dast-action@v1.0.0
        with:
          baseurl:  https://cloud.appscan.com
          asoc_key: ${{secrets.ASOC_KEY}}
          asoc_secret: ${{secrets.ASOC_SECRET}}
          application_id: acd3ef50-6276-461d-8514-abc6e7113577
          scan_type: 'staging'
          dynamic_scan_type: dast
          starting_URL: 'https://demo.testfire.net?mode=demo'
          network: public
          fail_for_noncompliance: false
          wait_for_analysis: true

```

# Example 2 - DAST scan using a .scant template file with private network through appscan presence
```yaml
name: "HCL AppScan DAST"
on:
  workflow_dispatch
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      - name: Run ASoC DAST Scan
        uses: antonychiu2/asoc-dast-action@v1.0.0
        with:
          baseurl:  https://cloud.appscan.com
          asoc_key: ${{secrets.ASOC_KEY}}
          asoc_secret: ${{secrets.ASOC_SECRET}}
          application_id: acd3ef50-6276-461d-8514-abc6e7113577
          scan_type: 'staging'
          dynamic_scan_type: upload
          scan_or_scant_file: 'altoro.scant'
          network: private
          presence_id: f185efda-67bf-ed11-ba76-14cb65723612
          fail_for_noncompliance: false
          wait_for_analysis: true

```
