# Security Policy

## Supported Versions

Security fixes are intended for the latest published stable release of SOC Sentinel.

| Version | Security support |
| --- | --- |
| Latest published stable release | Supported |
| Earlier releases | Not guaranteed |

Users are encouraged to upgrade to the latest stable release before reporting an issue, where practical.

## Reporting a Vulnerability

Please do not report suspected security vulnerabilities through public GitHub issues, discussions, pull requests, or other public channels.

Use GitHub's Private vulnerability reporting feature for the SOC Sentinel repository when it is enabled.

To submit a report:

1. Open the SOC Sentinel GitHub repository.
2. Navigate to the Security tab.
3. Open the Advisories or private vulnerability reporting section.
4. Select Report a vulnerability and submit the report privately.

If the private reporting option is not available, use a private communication channel listed on the repository maintainer's GitHub profile. Do not post vulnerability details publicly while seeking a reporting contact.

## What to Include

Please include as much of the following information as you can safely provide:

- A concise description of the suspected vulnerability.
- The affected SOC Sentinel release, version, or commit.
- The Python version and operating environment, if relevant.
- Clear steps to reproduce the issue.
- The potential impact on users or systems processing security events with SOC Sentinel.
- Relevant logs, error messages, or proof-of-concept material.

Before submitting, remove passwords, API keys, tokens, personal information, private log data, and other sensitive material.

## Scope

This policy covers security issues in SOC Sentinel's maintained source code, packaging, supported command-line workflows, event and file processing, configuration, and any integrations maintained by this project.

Examples of relevant reports include:

- Unsafe handling of malformed or specially crafted event files.
- Exposure of sensitive information through logs, errors, or reports.
- Insecure handling of configuration values or integration credentials.
- Unexpected command or code execution caused by SOC Sentinel.
- Vulnerabilities in dependencies as they affect SOC Sentinel.

This policy does not make a claim that every third-party dependency or external service is maintained by the SOC Sentinel project.

## Response and Disclosure

Reports will be reviewed as maintainer availability permits. The maintainer may request additional information to reproduce and assess a report.

Confirmed issues will be evaluated and addressed as appropriate. Please allow a reasonable opportunity for investigation and remediation before making vulnerability details public.

No fixed acknowledgement, resolution, or remediation timeframe is guaranteed.
