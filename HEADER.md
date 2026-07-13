<!--
  Keep the title and badges OUTSIDE the centered <div>: the Terraform Registry's markdown renderer
  does not parse markdown inside an HTML block, so a # heading or [![badge]] in the div renders as
  literal text on the registry. Only the logo (HTML) goes in the div.
-->
<div align="center">
  <a href="https://libredevops.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
      <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="300">
    </picture>
  </a>
</div>

# Terraform MSGraph XDR Custom Detection Rules

Microsoft Defender XDR **custom detection rules as code**: analysts author one YAML file per rule,
Terraform validates every field at plan time and deploys through the Microsoft Graph
`security/rules/detectionRules` API using the
[Microsoft/msgraph](https://registry.terraform.io/providers/Microsoft/msgraph/latest) provider.
A curated baseline ships in the box (the same catalog and engine shape as the Libre DevOps policy
and Sentinel workbook modules), and destructive automated response actions sit behind an explicit
gate.

[![CI](https://github.com/libre-devops/terraform-msgraph-xdr-custom-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/libre-devops/terraform-msgraph-xdr-custom-detection-rules/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libre-devops/terraform-msgraph-xdr-custom-detection-rules?sort=semver&label=release)](https://github.com/libre-devops/terraform-msgraph-xdr-custom-detection-rules/releases/latest)
[![Terraform Registry](https://img.shields.io/badge/registry-libre--devops-7B42BC?logo=terraform&logoColor=white)](https://registry.terraform.io/namespaces/libre-devops)
[![License](https://img.shields.io/github/license/libre-devops/terraform-msgraph-xdr-custom-detection-rules)](./LICENSE)

---

## Detections as code, analyst first

A detection engineer should review a detection the way a developer reviews code: one file, one
rule, one diff. This module makes that the deployment contract:

```
custom-detections/
  identity/
    impossible-travel-vpn-gap.yaml
  endpoint/
    certutil-remote-download.yaml
  email/
    forwarding-rule-to-external.yaml
```

Every `*.yaml` (or `*.yml`) under the directory you pass as `custom_detections_dir` becomes one
custom detection rule; the first level folder is its **category**, the analyst facing logical
grouping that also drives the `rules_by_category` and `mitre_coverage` outputs. A rule file looks
like this:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/libre-devops/terraform-msgraph-xdr-custom-detection-rules/main/schema/custom-detection.schema.json
display_name: Certutil used to download remote content
status: enabled            # enabled | disabled (default enabled)
frequency: PT3H            # PT0S (Continuous) | PT1H | PT3H | PT12H | PT24H
query: |
  DeviceProcessEvents
  | where FileName =~ "certutil.exe"
  | where ProcessCommandLine has_any ("urlcache", "-split") and ProcessCommandLine has "http"
  | project Timestamp, ReportId, DeviceId, DeviceName, AccountSid, SHA256, ProcessCommandLine
alert:
  severity: medium         # informational | low | medium | high
  recommended_actions: Recover and detonate the downloaded content.
  mitre:
    - tactic: CommandAndControl
      techniques: [T1105]
  custom_details:
    CommandLine: ProcessCommandLine
  entity_mappings:
    hosts:
      - device_id_column: DeviceId
        name_column: DeviceName
    files:
      - sha256_column: SHA256
device_groups: [Workstations-Corp]   # optional scoping
```

The same schema works as HCL through `custom_rules` for rules a stack composes or generates, and
the module's own `catalog/` baseline uses it too: one validator, one normaliser, three sources,
**deployed simultaneously** (YAML directory, HCL rules and the baseline coexist in one call; rule
ids must be unique across all three, and the plan names any collision).

## Every field checked, every error named

The plan fails with **every** problem across **every** file in one message, each naming the
offending file and field: unknown attributes at any nesting level, missing required fields, enum
and format violations (severity, status, ISO 8601 schedule against `allowed_frequencies`,
`T1059.001` style technique ids, the 14 enterprise ATT&CK tactics), non list or non mapping shapes,
and duplicate rule ids across sources. The allowed shapes are extracted from the Graph beta
`$metadata` (all 17 entity mapping types, all 16 automated action groups) and mirrored in
`schema/custom-detection.schema.json`, so editors with yaml-language-server flag mistakes while the
analyst types, and CI can pre-check files with the same schema before Terraform runs.

Values are also **normalised on a best endeavours basis**, because analysts author these files:
keys stay strict (they are the schema contract editors autocomplete), values are forgiving.
`status`, `severity` and `isolation_type` are case insensitive; `frequency` and technique ids
uppercase themselves (`pt1h` becomes `PT1H`, `t1110` becomes `T1110`); tactics resolve case and
separator insensitively (`credential access`, `credential-access` and `CredentialAccess` all
deploy as `CredentialAccess`, and the British `DefenceEvasion` maps to the API's
`DefenseEvasion`). Truly unknown values still fail the plan with the canonical list named, and
the editor schema keeps nudging the canonical spellings.

Two advisory checks warn without failing: a query that does not visibly return `Timestamp` and
`ReportId` (custom detections must output them; rename projections can hide them from the token
scan), and a rule with no MITRE mapping (it would vanish from coverage reporting).

## Built on the current API shape

Microsoft is removing the legacy detection rule properties on **2026-10-01** (`isEnabled`,
`detectorId`, `lastRunDetails`, `alertTemplate.category`, `mitreTechniques`, `impactedAssets`,
`responseActions`). This module never used them: it builds on `status`, `tactics` with nested
techniques, `entityMappings`, and `automatedActions` from day one. Custom detection rules are beta
only today, so `api_version` defaults to `beta`; it is a plain variable, so flip it to `v1.0` the
day Microsoft promotes the API, without waiting for a module release.

## Live API reality, encoded

The beta docs and the live service disagree in places; every divergence below was hit on a real
tenant and is now encoded in the module rather than left for you to find:

- **One tactic per rule.** The docs model `tactics` as a collection; the service 400s on more than
  one ("Only one tactic is currently supported"). Authoring keeps the full list, the body sends
  only the first tactic, and the `rules` / `mitre_coverage` outputs report everything authored,
  ready to send in full the day the API accepts it.
- **Mail message mappings have a mandatory column combination.** Network message id, recipient and
  sender must map together (a lesser pair 400s with "at least one mandatory field combination");
  the validator enforces it and subject is recommended.
- **Deletes can hang server side** (observed via both the API and the portal). The rule resource
  carries a 10 minute delete timeout and transient error retries by default (`timeouts`,
  `retry_error_message_regex`), so a wedged delete fails loudly instead of spinning.
- **Portability is a catalog quality bar.** Catalog rules only use hunting tables that resolve in
  any Defender XDR tenant (Device*, Email*, Identity*, CloudApp*). Entra specific tables like
  `AadSignInEventsBeta` only resolve when that data flows into XDR, so a rule on them fails both
  remote validation and the create elsewhere; the in graph validation catches this before anything
  deploys, which is exactly its job.

## Automated response actions are a deliberate opt in

A detection rule can act on real assets when it fires: isolate devices, disable users, quarantine
files, delete mail. The module refuses any rule carrying `automated_actions`, from any source,
until the call sets `allow_automated_actions = true`, and the failure names the files. Turning the
gate on is a reviewed decision for the calling stack, never a side effect of dropping a file into a
folder.

## The curated baseline

`baseline_enabled` (on by default) deploys the reviewed starter pack from `catalog/`, currently six
high signal, low noise rules across `endpoint/`, `identity/`, `email/` and `cloud-apps/` (Office
spawning encoded PowerShell, LSASS dump tooling, failed sign-in bursts, legacy authentication
sign-ins, delivered malware verdict mail, mass cloud app downloads). None carry automated actions.
Tune or drop each through `baseline_overrides` (disable, park in `status = disabled` tuning mode,
reschedule, retune severity, scope to device groups); the `baseline_catalog_keys` output lists the
keys. Rules deploy with client provided ids (the file name, unless the file sets `id`), so plans
are stable, and `id_prefix` namespaces everything a call owns for side by side deployments.

## Validation ladder (CI/CD)

1. **Editor**: yaml-language-server against `schema/custom-detection.schema.json` while typing.
2. **Plan**: this module's validator, offline, every field, every file, one aggregated failure.
3. **CI, local lint**: KQL syntax parsing (Kusto.Language) via the LibreDevOpsHelpers gate, fast
   feedback on pull requests before anything touches the tenant.
4. **Apply, in graph**: `remote_query_validation` (on by default) runs every rule's query against
   the tenant's real advanced hunting schema through the Graph v1.0 `security/runHuntingQuery`
   action, inside the Terraform graph and before the rule resource itself. Queries run **verbatim**
   by default (the endpoint caps result sizes server side); `remote_validation_append_take` can
   append a trailing `| take 1` for queries that tolerate it, off by default because appending an
   operator can interact badly with a query that already ends in one. The response schema (the
   query's output columns) is tracked in state, and a query change replaces its validation action,
   so re-validation happens exactly when a query changes. A missing table or column fails the
   apply with the rule named.
5. **Apply, the create**: the Graph detection rule create is the final authority (it validates the
   query and the required result columns server side).

## Permissions

| Path | Permission |
| ---- | ---------- |
| Deploy rules (app or delegated) | `CustomDetection.ReadWrite.All` |
| Remote query validation (in graph, default on; also usable from CI) | `ThreatHunting.Read.All` |

Delegated callers also need a Defender XDR role that manages detections (Security Administrator,
or unified RBAC **Detection tuning (Manage)**). The provider authenticates from the environment
(Azure CLI locally, OIDC in CI) like the azuread provider.

## Outputs made for a SOC

`mitre_coverage` rolls the authored tactics and techniques up into ATT&CK coverage per rule ids,
ready for a coverage report or workbook; `rules_by_category` and `rules` expose the analyst view;
`ids` / `ids_zipmap` follow the estate composition conventions.
