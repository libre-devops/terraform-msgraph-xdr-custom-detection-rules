<!--
  Header for the minimal example README. Edit this file, then run `just docs`
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

# Minimal example

The smallest valid call: the curated baseline switched off and a single analyst authored YAML rule
picked up from `custom-detections/canary/`. The canary rule hunts for a file name that cannot
exist, so a live apply exercises the full create, update and delete lifecycle without ever raising
an alert. Needs `CustomDetection.ReadWrite.All` on a Defender XDR tenant.

<!-- BEGIN_TF_DOCS -->
## Example configuration

```hcl
module "detection_rules" {
  source = "../.."

  # The smallest valid call: no curated baseline, one analyst authored rule picked up from the
  # custom-detections directory (one YAML file per rule, first level folder = category). The canary
  # rule matches nothing by construction, so a live apply creates a rule that never fires.
  baseline_enabled      = false
  custom_detections_dir = "${path.module}/custom-detections"
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
| <a name="output_ids"></a> [ids](#output\_ids) | Rule id to Graph detection rule id. |
| <a name="output_rules"></a> [rules](#output\_rules) | Metadata for the deployed rules. |
<!-- END_TF_DOCS -->
