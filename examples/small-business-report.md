# Security Telemetry Coverage Report

Reference time (UTC): 2026-11-20T16:00:00+00:00

This report assesses declared telemetry availability and freshness. It does not measure detection effectiveness or complete security coverage.

Coverage is the Healthy share of assessed rows. Every status percentage uses all assessed rows in its table row as the denominator.

## Summary

| Assessed | Healthy | Stale | Missing | Unverified |
| --- | --- | --- | --- | --- |
| 12 | 8 (66.7%) | 1 (8.3%) | 2 (16.7%) | 1 (8.3%) |

## Security domains

| Domain | Assessed | Healthy | Stale | Missing | Unverified |
| --- | --- | --- | --- | --- | --- |
| Application | 1 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Cloud | 1 | 0 (0.0%) | 0 (0.0%) | 1 (100.0%) | 0 (0.0%) |
| Device | 1 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Email | 1 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Endpoint | 3 | 2 (66.7%) | 0 (0.0%) | 0 (0.0%) | 1 (33.3%) |
| Identity | 1 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Network | 2 | 1 (50.0%) | 1 (50.0%) | 0 (0.0%) | 0 (0.0%) |
| Recovery | 1 | 1 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Server | 1 | 0 (0.0%) | 0 (0.0%) | 1 (100.0%) | 0 (0.0%) |

## Findings

| Asset | Asset type | Telemetry source | Security domain | Criticality | Status | Last event (UTC) | Threshold (hours) | Explanation | Recommendation | Notes | Why it matters |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Paper Kite Cloud | Cloud account | Administrative audit | Cloud | Critical | Missing |  | 24 | Logging is disabled or the expected source is explicitly marked absent. | Enable or restore the source and confirm that a new event arrives. | Expected source was not provisioned in this scenario. | Cloud audit logs show who changed cloud resources, which helps establish an incident timeline. Without this telemetry, investigators may need other records to piece together what happened. |
| Paper Kite Identity | Identity service | Sign-ins | Identity | Critical | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Authentication events help analysts spot unusual sign-ins and investigate account misuse. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite File Server | File server | File access | Server | High | Missing |  | 24 | Logging is disabled or the expected source is explicitly marked absent. | Enable or restore the source and confirm that a new event arrives. | Fictional logging configuration is disabled. | Security logs help analysts reconstruct activity during an investigation. Without this telemetry, investigators may need other records to piece together what happened. |
| Paper Kite Backup | Backup service | Backup jobs | Recovery | High | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Security logs help analysts reconstruct activity during an investigation. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Finance Laptop | Workstation | Endpoint activity | Endpoint | High | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Endpoint logs help analysts see suspicious process activity and trace what happened on a device. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Gateway | Firewall | Connection events | Network | High | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Firewall and network logs help investigators reconstruct connections and identify blocked traffic. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Mail | Mail service | Message trace | Email | High | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Security logs help analysts reconstruct activity during an investigation. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Office Wi-Fi | Access point | Association events | Network | Medium | Stale | 2026-11-18T14&#58;00&#58;00+00&#58;00 | 24 | The last reported event is older than the freshness threshold. | Check the event producer, forwarding path, ingestion, and clocks. | Fictional collector has received no recent events. | Firewall and network logs help investigators reconstruct connections and identify blocked traffic. Stale telemetry can create a blind spot while analysts expect the source to be reporting. |
| Paper Kite Design Laptop | Workstation | Endpoint activity | Endpoint | Medium | Unverified | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | The inventory lacks sufficient reliable evidence of current coverage. | Confirm logging and source presence, then record a verified recent event and check clocks. | Receipt is recorded but has not been independently verified. | Endpoint logs help analysts see suspicious process activity and trace what happened on a device. Checking actual event delivery helps analysts avoid relying on an assumption. |
| Paper Kite Front Desk | Workstation | Endpoint activity | Endpoint | Medium | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Endpoint logs help analysts see suspicious process activity and trace what happened on a device. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Storefront | Web application | Access events | Application | Medium | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Security logs help analysts reconstruct activity during an investigation. A verified recent event gives analysts some evidence that this source is reporting. |
| Paper Kite Printer | Printer | Administrative events | Device | Low | Healthy | 2026-11-20T14&#58;00&#58;00+00&#58;00 | 24 | A verified source has a recent event within the freshness threshold. | Continue checking recent events during routine monitoring reviews. | Fictional collector receipt confirmed. | Security logs help analysts reconstruct activity during an investigation. A verified recent event gives analysts some evidence that this source is reporting. |
