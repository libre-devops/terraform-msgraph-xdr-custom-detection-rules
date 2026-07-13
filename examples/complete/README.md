<!--
  Header for the complete example README. Edit this file, then run `just docs`
  (or ./Sort-LdoTerraform.ps1 -IncludeExamples) to regenerate the section between the markers.
  The example's main.tf is embedded into the README automatically (see .terraform-docs.yml).
-->
<div align="center">
  <a href="https://libredevops.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
      <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="200">
    </picture>
  </a>
</div>

# Complete example

Every feature at once: the curated baseline with per rule overrides (a rule parked in disabled
tuning mode, another retuned to a quieter schedule and severity), analyst authored YAML rules from
`custom-detections/` including a doubly inert demonstration of the gated automated response
actions, an HCL authored rule through `custom_rules`, and an `id_prefix` namespacing everything the
call owns. Live applies stay alert free: the action carrying rule is disabled and unmatchable.
Needs `CustomDetection.ReadWrite.All` on a Defender XDR tenant.

<!-- BEGIN_TF_DOCS -->
## Example configuration

```hcl
module "detection_rules" {
  source = "../.."

  # The maximum surface: the curated baseline with per rule tuning, analyst YAML rules from the
  # directory (including one that demonstrates the gated automated actions), an HCL authored rule,
  # and an id prefix namespacing everything this call owns.
  custom_detections_dir = "${path.module}/custom-detections"
  id_prefix             = "ldo-"

  # The automated actions gate is a deliberate opt in; the only rule using it here is disabled and
  # matches nothing, so a live apply stays inert while proving the whole shape end to end.
  allow_automated_actions = true

  baseline_overrides = {
    # Tuning mode: keep the rule deployed but switched off while thresholds are reviewed.
    mass-file-download-by-user = { status = "disabled" }

    # Quieter schedule and severity for a noisy estate.
    legacy-authentication-successful-signin = {
      frequency = "PT24H"
      severity  = "low"
    }
  }

  # HCL authored rules use exactly the same schema as the YAML files; this path exists for rules a
  # stack composes or generates. The category attribute stands in for the folder name.
  custom_rules = {
    hcl-authored-signin-canary = {
      category     = "identity"
      display_name = "HCL authored canary (never matches)"
      frequency    = "PT24H"
      # IdentityLogonEvents resolves in any XDR tenant's hunting schema; the Entra specific
      # AadSignInEventsBeta does not (proven live), and portability is the catalog quality bar.
      query = "IdentityLogonEvents | where AccountUpn == \"ldo-never@example.invalid\" | project Timestamp, ReportId, AccountUpn, IPAddress"

      alert = {
        severity = "informational"
        mitre    = [{ tactic = "InitialAccess", techniques = ["T1078"] }]

        entity_mappings = {
          accounts = [{ upn_column = "AccountUpn" }]
          ips      = [{ address_column = "IPAddress" }]
        }
      }
    }
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0, < 2.0.0 |
| <a name="requirement_msgraph"></a> [msgraph](#requirement\_msgraph) | >= 0.1.0, < 1.0.0 |

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_detection_rules"></a> [detection\_rules](#module\_detection\_rules) | ../.. | n/a |

## Resources

No resources.

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_baseline_catalog_keys"></a> [baseline\_catalog\_keys](#output\_baseline\_catalog\_keys) | Every baseline rule id (the keys baseline\_overrides accepts). |
| <a name="output_ids_zipmap"></a> [ids\_zipmap](#output\_ids\_zipmap) | Rule id to {name, id} for composition. |
| <a name="output_mitre_coverage"></a> [mitre\_coverage](#output\_mitre\_coverage) | ATT&CK tactics and techniques mapped to the rules that cover them. |
| <a name="output_rules_by_category"></a> [rules\_by\_category](#output\_rules\_by\_category) | Rule ids grouped by their analyst facing category. |
<!-- END_TF_DOCS -->
