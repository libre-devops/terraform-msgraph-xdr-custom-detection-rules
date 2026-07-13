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
      query        = "AadSignInEventsBeta | where AccountUpn == \"ldo-never@example.invalid\" | project Timestamp, ReportId, AccountUpn, IPAddress"

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
