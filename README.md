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
ids must be unique across all three, and the plan names any collision). Alongside the machine
schema, [`schema/custom-detection-reference.yaml`](./schema/custom-detection-reference.yaml) is
the annotated human companion: every field with its defaults, allowed values, and the live API
caveats, ready to copy from.

**Brownfield tenants adopt in two commands** (LibreDevOpsHelpers 2.6.0+):
`Export-LdoCustomDetectionRule -OutDir ./custom-detections` turns every hand made rule in the
tenant into these YAML files (server ids kept so plans line up; legacy shapes converted best
endeavours with TODO comments), then after a plan,
`Invoke-LdoTerraformGraphImportFromPlan -PlanJson ./plan.json` imports them all into state.

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

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0, < 2.0.0 |
| <a name="requirement_msgraph"></a> [msgraph](#requirement\_msgraph) | >= 0.1.0, < 1.0.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_msgraph"></a> [msgraph](#provider\_msgraph) | >= 0.1.0, < 1.0.0 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [msgraph_resource.detection_rules](https://registry.terraform.io/providers/Microsoft/msgraph/latest/docs/resources/resource) | resource |
| [msgraph_resource_action.validate_queries](https://registry.terraform.io/providers/Microsoft/msgraph/latest/docs/resources/resource_action) | resource |
| [terraform_data.schema_guard](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_allow_automated_actions"></a> [allow\_automated\_actions](#input\_allow\_automated\_actions) | Gate for automated response actions. Automated actions run against real assets when a rule fires<br/>(isolate a device, disable a user, quarantine a file, delete mail, and so on), so no rule from any<br/>source (baseline, YAML directory, or custom\_rules) may carry an automated\_actions block until this<br/>is explicitly set true. The plan fails, naming the offending files, when a rule declares actions<br/>while the gate is off. Turning the gate on is a deliberate, reviewed decision for the calling stack. | `bool` | `false` | no |
| <a name="input_allowed_frequencies"></a> [allowed\_frequencies](#input\_allowed\_frequencies) | The ISO 8601 durations a rule's `frequency` may use. Defaults to the schedules Defender XDR custom<br/>detections support: every 1, 3, 12, or 24 hours (PT1H, PT3H, PT12H, PT24H, with P1D accepted as the<br/>24 hour spelling) plus PT0S for Continuous (near real time). Narrow this list to enforce an<br/>organisational floor (for example, forbid Continuous), or extend it if the service starts accepting<br/>new schedules before this module catches up. | `list(string)` | <pre>[<br/>  "PT0S",<br/>  "PT1H",<br/>  "PT3H",<br/>  "PT12H",<br/>  "PT24H",<br/>  "P1D"<br/>]</pre> | no |
| <a name="input_api_version"></a> [api\_version](#input\_api\_version) | Microsoft Graph API version used for every detection rule call. Custom detection rules are<br/>currently beta only, so the default is beta; flip to v1.0 when Microsoft promotes the API. Never<br/>hardcoded so consumers are not pinned to this module's release cadence. | `string` | `"beta"` | no |
| <a name="input_baseline_enabled"></a> [baseline\_enabled](#input\_baseline\_enabled) | Deploy the curated baseline detections shipped in this module's catalog/ directory (the same shape<br/>as the policy module's baseline: calling the module gets a reviewed starter pack for free). Each<br/>baseline rule is a YAML file under catalog/<category>/ and can be tuned or dropped per rule through<br/>baseline\_overrides. Set false to deploy only your own rules. | `bool` | `true` | no |
| <a name="input_baseline_overrides"></a> [baseline\_overrides](#input\_baseline\_overrides) | Per rule tuning of the baseline, keyed by the baseline rule id (the id field in the catalog YAML,<br/>which defaults to the file name; the baseline\_catalog\_keys output lists every key). Recognised<br/>attributes per entry, all optional:<br/><br/>- enabled (bool): false drops the rule entirely.<br/>- status (string): enabled or disabled, overriding the catalog value (deploy a rule in a disabled,<br/>  tuning-mode state without forking the catalog).<br/>- frequency (string): override the schedule (validated against allowed\_frequencies).<br/>- severity (string): override the alert severity.<br/>- device\_groups (list(string)): scope the rule to specific device groups.<br/><br/>Unknown keys, and keys that match no baseline rule, fail the plan. | `any` | `{}` | no |
| <a name="input_custom_detections_dir"></a> [custom\_detections\_dir](#input\_custom\_detections\_dir) | Root directory of analyst authored detection rules, picked up per file: every *.yaml or *.yml under<br/><dir>/<category>/ becomes one custom detection rule, and the first level folder name is the rule's<br/>category (its logical grouping for humans and for the mitre\_coverage / rules\_by\_category outputs).<br/>Files directly in the root land in the "uncategorised" category. Each file follows the schema in<br/>schema/custom-detection.schema.json (every field is validated at plan time with the offending file<br/>named). Null deploys no directory rules. | `string` | `null` | no |
| <a name="input_custom_rules"></a> [custom\_rules](#input\_custom\_rules) | Detection rules authored directly in HCL, keyed by rule id, using exactly the same schema as the<br/>YAML files (display\_name, query, frequency, alert {severity, mitre, entity\_mappings, ...},<br/>device\_groups, automated\_actions, extra\_body; a category attribute is also accepted since HCL rules<br/>have no folder to derive it from). YAML files are the analyst path; this input exists for rules<br/>that are generated or composed by the calling stack. Validated by the same engine as the files. | `any` | `{}` | no |
| <a name="input_hunting_api_version"></a> [hunting\_api\_version](#input\_hunting\_api\_version) | Microsoft Graph API version for the remote query validation calls (security/runHuntingQuery).<br/>Defaults to v1.0, where the hunting API is generally available; independent of api\_version because<br/>the detection rule API and the hunting API promote separately. | `string` | `"v1.0"` | no |
| <a name="input_id_prefix"></a> [id\_prefix](#input\_id\_prefix) | Optional prefix prepended to every rule id (baseline and custom), namespacing the rules this module<br/>call owns, for example per environment or per stack ("soc-dev-"). The rule id is client provided on<br/>create and doubles as the Terraform key, so the prefix keeps parallel deployments from colliding.<br/>Null applies no prefix. | `string` | `null` | no |
| <a name="input_remote_query_validation"></a> [remote\_query\_validation](#input\_remote\_query\_validation) | Run every rule's KQL against the tenant through the Graph runHuntingQuery action inside the<br/>Terraform graph, before the rule is created or updated. This proves tables and columns against the<br/>real advanced hunting schema server side (queries run verbatim by default; see<br/>remote\_validation\_append\_take), and the response schema (the query's output columns) is tracked in<br/>state. A query change replaces<br/>its validation action, so re-validation happens exactly when a query changes. The applying<br/>principal needs ThreatHunting.Read.All; set false to opt out (for example, a principal with only<br/>CustomDetection.ReadWrite.All). | `bool` | `true` | no |
| <a name="input_remote_validation_append_take"></a> [remote\_validation\_append\_take](#input\_remote\_validation\_append\_take) | Append a trailing "\| take 1" to each remote validation query. Off by default on purpose: appending<br/>an operator can interact badly with queries that already end in a take or limit, or whose final<br/>operator matters, so the default runs every query verbatim and relies on the hunting endpoint's own<br/>server side result caps. Enable it deliberately when your queries tolerate a trailing take and you<br/>want validation to return as little data as possible. | `bool` | `false` | no |
| <a name="input_remote_validation_timespan"></a> [remote\_validation\_timespan](#input\_remote\_validation\_timespan) | ISO 8601 timespan the remote validation queries look back over. Validation needs schema soundness,<br/>not data, so the default PT1H keeps the scanned window (and the tenant load) minimal; widen it if<br/>you want validation to double as a smoke test over real data. | `string` | `"PT1H"` | no |
| <a name="input_retry_error_message_regex"></a> [retry\_error\_message\_regex](#input\_retry\_error\_message\_regex) | Regular expressions the provider retries on when a Graph call fails, applied to the detection rule<br/>resource and the validation actions. Transient service noise is retried by default; the provider<br/>retries matching errors with backoff until the operation timeout bounds it (the provider exposes no<br/>retry count knob, so the timeout is the ceiling). Set null to disable retries. | `list(string)` | <pre>[<br/>  "(?i)too many requests",<br/>  "(?i)service unavailable",<br/>  "(?i)internal server error",<br/>  "(?i)timeout",<br/>  "(?i)temporarily unavailable"<br/>]</pre> | no |
| <a name="input_timeouts"></a> [timeouts](#input\_timeouts) | Operation timeouts for the detection rule resource. The delete default is 10 minutes because rule<br/>deletion was observed hanging server side (live, via both the API and the portal): a wedged delete<br/>now fails loudly at the timeout instead of spinning into the provider default, and transient errors<br/>retry per retry\_error\_message\_regex. | <pre>object({<br/>    create = optional(string, "10m")<br/>    delete = optional(string, "10m")<br/>    read   = optional(string, "5m")<br/>    update = optional(string, "10m")<br/>  })</pre> | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_baseline_catalog_keys"></a> [baseline\_catalog\_keys](#output\_baseline\_catalog\_keys) | Every baseline rule id in this module's catalog (the keys baseline\_overrides accepts), whether or not the baseline is enabled. |
| <a name="output_ids"></a> [ids](#output\_ids) | Map of rule id to the Graph detection rule id (client provided, so normally identical; kept as a map for composition symmetry with the estate). |
| <a name="output_ids_zipmap"></a> [ids\_zipmap](#output\_ids\_zipmap) | Map of rule id to {name, id} for easy composition, matching the estate wide zipmap convention. |
| <a name="output_mitre_coverage"></a> [mitre\_coverage](#output\_mitre\_coverage) | ATT&CK coverage rolled up from the authored mitre blocks: tactics and techniques each map to the rule ids that cover them. Feeds the coverage report and workbooks. |
| <a name="output_rules"></a> [rules](#output\_rules) | Metadata for every deployed rule: display name, category, source (baseline, custom\_detections\_dir, or custom\_rules), the file it came from, status, schedule, severity, and its MITRE tactics and techniques. |
| <a name="output_rules_by_category"></a> [rules\_by\_category](#output\_rules\_by\_category) | Rule ids grouped by category (the analyst facing logical separation: the first level folder for file rules, the category attribute or "custom" for HCL rules). |
<!-- END_TF_DOCS -->
