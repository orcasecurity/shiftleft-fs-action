# Orca Shift Left Security Action

[GitHub Action](https://github.com/features/actions)
for [Orca Shift Left Security](https://orca.security/solutions/shift-left-security/)

#### More info can be found in the official Orca Shift Left Security<a href="https://docs.orcasecurity.io/v1/docs/shift-left-security"> documentation</a>

## Table of Contents

- [Usage](#usage)
  - [Workflow](#workflow)
  - [Inputs](#inputs)
- [Annotations](#annotations)
- [Upload SARIF report](#upload-sarif-report)

## Usage

### Workflow

```yaml
name: Sample Orca FS Scan Workflow
on:
  # Scan for each push event on your protected branch. If you have a different branch configured, please adjust the configuration accordingly by replacing 'main'.
  push:
    branches: ["main"]
  # NOTE: To enable scanning for pull requests, uncomment the section below.
  #pull_request:
  #branches: [ "main" ]
  # NOTE: To schedule a daily scan at midnight, uncomment the section below.
  #schedule:
  #- cron: '0 0 * * *'
jobs:
  orca-fs-scan:
    name: Orca fs Scan
    runs-on: ubuntu-latest
    env:
      PROJECT_KEY: <project key> # Set the desired project to run the cli scanning with
    steps:
      # Checkout your repository under $GITHUB_WORKSPACE, so your job can access it
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run Orca FS Scan
        uses: orcasecurity/shiftleft-fs-action@v1
        with:
          api_token: ${{ secrets.ORCA_SECURITY_API_TOKEN }}
          project_key: ${{ env.PROJECT_KEY }}
          path:
            # scanning the entire repository
            "."
```

### Inputs

| Variable                     | Example Value &nbsp;         | Description &nbsp;                                                                         | Type    | Required | Default      |
| ---------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------ | ------- | -------- | ------------ |
| api_token                    |                              | Orca API Token used for Authentication                                                     | String  | Yes      | N/A          |
| project_key                  | my-project-key               | Project Key name                                                                           | String  | Yes      | N/A          |
| path                         | sub-dir                      | Path to scan                                                                               | String  | Yes      | N/A          |
| format                       | json                         | Format for displaying the results                                                          | String  | No       | cli          |
| output                       | results/                     | Output directory for scan results                                                          | String  | No       | N/A          |
| no_color                     | false                        | Disable color output                                                                       | Boolean | No       | false        |
| exit_code                    | 10                           | Exit code for failed execution due to policy violations                                    | Integer | No       | 3            |
| control_timeout              | 30                           | Number of seconds the control has to execute before being canceled                         | Integer | No       | 60           |
| silent                       | false                        | Disable logs and warnings output                                                           | Boolean | No       | false        |
| console_output               | json                         | Prints results to console in the provided format (only when --output is provided)          | String  | No       | cli          |
| config                       | config.json                  | path to configuration file (json, yaml or toml)                                            | String  | No       | N/A          |
| show_annotations             | true                         | show github annotations on pull requests                                                   | Boolean | No       | true         |
| disable_secret               | true                         | Disables the secret detection scanning                                                     | Boolean | No       | false        |
| exceptions_filepath          | n/a                          | exceptions YAML filepath. (File should be mounted)                                         | String  | No       | false        |
| hide_vulnerabilities         | n/a                          | do not show detailed view of the vulnerabilities findings                                  | Boolean | No       | false        |
| custom_secret_controls       | custom_rules.yaml            | path to custom secret controls file                                                        | String  | No       | N/A          |
| num_cpu                      | 10                           | Number of logical CPUs to be used for secret scanning (default 10)                         | Integer | No       | 10           |
| show_failed_issues_only      | n/a                          | show only failed issues                                                                    | Boolean | No       | false        |
| display_name                 | custom-display-name          | Scan log display name (on Orca platform)                                                   | String  | No       | N/A          |
| hide_skipped_vulnerabilities | false                        | Filter out skipped vulnerabilities from result                                             | Boolean | No       | false        |
| exclude_paths                | ./notToBeScanned/,example.tf | List of paths to be excluded from scan (comma-separated)                                   | String  | No       | N/A          |
| max_secret                   | 10                           | Set the maximum secrets that can be found, when reaching this number secret scan will stop | Integer | No       | 10000        |
| dependency_tree              | false                        | Show dependency origin tree of vulnerable packages                                         | Boolean | No       | false        |
| security_checks              | secret                       | List of security issues to detect (comma-separated)                                        | String  | No       | vulns,secret |
| debug                        | true                         | Debug mode                                                                                 | Boolean | No       | false        |
| log_path                     | results/                     | The directory path to specify where the logs should be written to on debug mode.           | String  | No       | working dir  |
| disable_active_verification  | true                         | Disable active verification of secrets                                                     | Boolean | No       | false        |

## Annotations

After scanning, the action will add the results as annotations in a pull request:

![](/assets/secret_annotation_preview.png)

> **NOTE:** Annotations can be disabled by setting the "show_annotation" input to "false"

## Upload SARIF report

If you have [GitHub code scanning](https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/about-code-scanning) available you can use Orca Shift Left Security as a scanning tool

> **NOTE:** Code scanning is available for all public repositories. Code scanning is also available in private repositories owned by organizations that use GitHub Enterprise Cloud and have a license for GitHub Advanced Security.

Configuration:

```yaml
name: Scan and upload SARIF

push:
  branches:
    - main

jobs:
  orca-fs_scan:
    name: Orca FS Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    env:
      PROJECT_KEY: <project key> # Set the desired project to run the cli scanning with
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run Orca FS Scan
        id: orcasecurity_fs_scan
        uses: orcasecurity/shiftleft-fs-action@v1
        with:
          api_token: ${{ secrets.ORCA_SECURITY_API_TOKEN }}
          project_key: ${{ env.PROJECT_KEY }}
          path: <path to scan>
          format: "sarif"
          output: "results/"
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        if: ${{ always() && steps.orcasecurity_fs_scan.outputs.exit_code != 1 }}
        with:
          sarif_file: results/file_system.sarif
```

The results list can be found on the security tab of your GitHub project and should look like the following image
![](/assets/code_scanning_list.png)

An entry should describe the error and in which line it occurred
![](/assets/code_scanning_entry.png)
