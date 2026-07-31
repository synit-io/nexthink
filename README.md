# synit.io Nexthink

`synit-nexthink` provides PowerShell modules, enrichment scripts, NQL queries, and Remote Actions for extending Nexthink with external security and IT context.

## About Nexthink

Nexthink is a Digital Employee Experience (DEX) platform used by IT teams to monitor endpoint health, understand user impact, and drive proactive remediation. Enriching Nexthink with trusted third-party signals helps teams improve visibility, prioritization, and automation.

## Purpose

This repository provides integrations and automation designed to:

- Correlate external telemetry with endpoint and application context.
- Extend the Nexthink data model with actionable security and IT insights.
- Collect diagnostic data and remediate endpoint issues through Remote Actions.
- Support scalable PowerShell and NQL workflows in enterprise environments.

## Project Structure

```text
.
├── modules/
│   └── crowdstrike/
├── remoteactions/
│   ├── datacollection/
│   └── remediation/
├── LICENSE
└── README.md
```

- `modules/`: Reusable integrations and enrichment logic, grouped by provider.
- `remoteactions/datacollection/`: Remote Actions that collect and export endpoint data.
- `remoteactions/remediation/`: Location for Remote Actions that change or repair endpoint state.

## Available Modules

### CrowdStrike

The [CrowdStrike module](./modules/crowdstrike) correlates file hashes exported from Nexthink with CrowdStrike vulnerability data.

It includes:

- `CrowdStrikeSoftwareVulnByHash.psm1`: Reusable CrowdStrike API and enrichment functions.
- `enrichment_api/Nexthink-Enrich_Binaries.ps1`: Nexthink enrichment workflow.
- `nql/binaries_export.nql`: NQL query for exporting binary data used by the workflow.

See the [CrowdStrike module documentation](./modules/crowdstrike/README.md) for configuration and usage.

## Remote Actions

Remote Actions target Windows PowerShell 5.1 and are designed for silent, resilient, and repeatable execution through Nexthink.

## Managed Services

[synit.io Nexthink Insights & Automation](https://www.synit.io/services/nexthink) helps organizations continuously improve existing Nexthink environments through NQL analysis, data enrichment, Remote Actions, automation, reporting, and cross-team DEX insights.

### PowerShell Remote Actions as a Service

**PowerShell Remote Actions as a Service (PSRAaaS)** is available as a standalone offer or as part of the ongoing Nexthink Managed Service. It covers:

- Assessment of use-case suitability, scope, permissions, privacy, and potential side effects.
- Development or optimization of PowerShell Remote Actions with clear inputs, outputs, and error handling.
- Controlled testing with pilot groups, approvals, and rollback considerations.
- Operational handoff with versioning, documentation, execution data, and an optimization path.

Existing Remote Actions can also be reviewed, secured, and optimized. See [Nexthink Managed Service and PSRAaaS](https://www.synit.io/services/nexthink) for details.

## Maintainer

This project is maintained by [synit.io](https://www.synit.io).

## Contributing

Contributions are welcome. To propose improvements, new integrations, or fixes, open an issue or submit a pull request.

By contributing, you agree that your contributions may be used and distributed under this repository's license.

## License
This project is licensed under the Synit Repository License (SRL) v1.1.

You may use it for free for personal, educational, evaluation, and internal
business purposes, including internal production use inside your own company.

You may not offer it as a SaaS, hosted product, managed service, reseller
offering, distributor offering, service-provider solution, paid integration,
or other commercial third-party service without prior written permission from
synit.io.

This is a source-available license, not an open-source license.

See [LICENSE](./LICENSE).
