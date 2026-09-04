# Plan-time tests with a mocked msgraph provider: no cloud, no credentials. They pin the contract:
# the curated baseline deploys by default, overrides tune or drop rules, YAML and HCL rules flow
# through one normaliser (snake_case in, Graph camelCase out), and the schema guard fails a plan
# that carries any invalid file, naming it.

mock_provider "msgraph" {}

run "baseline_deploys_by_default" {
  command = plan

  assert {
    condition     = length(msgraph_resource.detection_rules) == 6
    error_message = "The curated baseline should deploy exactly its six catalog rules by default."
  }

  assert {
    condition     = alltrue([for k, r in msgraph_resource.detection_rules : r.body.status == "enabled"])
    error_message = "Every baseline rule ships enabled."
  }

  assert {
    condition     = msgraph_resource.detection_rules["office-app-spawns-encoded-powershell"].body.detectionAction.alertTemplate.severity == "high"
    error_message = "The Office to PowerShell rule should carry high severity."
  }

  assert {
    condition     = msgraph_resource.detection_rules["office-app-spawns-encoded-powershell"].body.schedule.frequency == "PT1H"
    error_message = "The Office to PowerShell rule should run hourly."
  }

  assert {
    condition     = msgraph_resource.detection_rules["lsass-memory-dump-tooling"].body.detectionAction.alertTemplate.tactics[0].techniques[0].subTechniques[0] == "T1003.001"
    error_message = "Nested sub techniques should normalise into subTechniques."
  }

  assert {
    condition     = length(msgraph_resource.detection_rules["office-app-spawns-encoded-powershell"].body.detectionAction.alertTemplate.tactics) == 1 && length(output.rules["office-app-spawns-encoded-powershell"].tactics) == 2
    error_message = "Multi tactic authoring sends only the first tactic to the API but reports all of them in the outputs."
  }

  assert {
    condition     = output.rules_by_category["endpoint"] == tolist(["lsass-memory-dump-tooling", "office-app-spawns-encoded-powershell"])
    error_message = "Categories should derive from the catalog folder names."
  }

  assert {
    condition     = contains(keys(output.mitre_coverage.techniques), "T1566.001")
    error_message = "MITRE coverage should roll techniques up across rules."
  }

  assert {
    condition     = length(msgraph_resource_action.validate_queries) == 6
    error_message = "Remote query validation is on by default: one runHuntingQuery action per rule."
  }

  assert {
    condition     = !endswith(msgraph_resource_action.validate_queries["office-app-spawns-encoded-powershell"].body.Query, "| take 1")
    error_message = "Validation queries run verbatim by default; nothing is appended unless remote_validation_append_take is set."
  }

  assert {
    condition     = msgraph_resource_action.validate_queries["office-app-spawns-encoded-powershell"].body.Timespan == "PT1H"
    error_message = "Validation queries should use the configured lookback timespan."
  }
}

run "remote_validation_take_append_opt_in" {
  command = plan

  variables {
    remote_validation_append_take = true
  }

  assert {
    condition     = endswith(msgraph_resource_action.validate_queries["office-app-spawns-encoded-powershell"].body.Query, "| take 1")
    error_message = "With remote_validation_append_take on, validation queries gain a trailing take 1."
  }
}

run "remote_validation_opt_out" {
  command = plan

  variables {
    remote_query_validation = false
  }

  assert {
    condition     = length(msgraph_resource_action.validate_queries) == 0
    error_message = "remote_query_validation = false should deploy no validation actions."
  }

  assert {
    condition     = length(msgraph_resource.detection_rules) == 6
    error_message = "Opting out of remote validation should not affect the rules themselves."
  }
}

run "overrides_tune_and_drop" {
  command = plan

  variables {
    id_prefix = "soc-"
    baseline_overrides = {
      mass-file-download-by-user              = { enabled = false }
      legacy-authentication-successful-signin = { status = "disabled", frequency = "PT24H", severity = "low" }
    }
  }

  assert {
    condition     = length(msgraph_resource.detection_rules) == 5
    error_message = "enabled = false should drop a baseline rule."
  }

  assert {
    condition     = !contains(keys(msgraph_resource.detection_rules), "soc-mass-file-download-by-user")
    error_message = "The dropped rule should not deploy."
  }

  assert {
    condition     = msgraph_resource.detection_rules["soc-legacy-authentication-successful-signin"].body.status == "disabled"
    error_message = "A status override should park the rule disabled."
  }

  assert {
    condition     = msgraph_resource.detection_rules["soc-legacy-authentication-successful-signin"].body.schedule.frequency == "PT24H"
    error_message = "A frequency override should reschedule the rule."
  }

  assert {
    condition     = msgraph_resource.detection_rules["soc-legacy-authentication-successful-signin"].body.detectionAction.alertTemplate.severity == "low"
    error_message = "A severity override should retune the alert."
  }

  assert {
    condition     = alltrue([for k in keys(msgraph_resource.detection_rules) : startswith(k, "soc-")])
    error_message = "id_prefix should namespace every rule id."
  }
}

run "yaml_and_hcl_share_one_normaliser" {
  command = plan

  variables {
    baseline_enabled      = false
    custom_detections_dir = "tests/fixtures/valid"
    custom_rules = {
      hcl-fixture = {
        category     = "identity"
        display_name = "HCL fixture"
        frequency    = "PT12H"
        query        = "AadSignInEventsBeta | project Timestamp, ReportId, AccountUpn"
        alert = {
          severity        = "medium"
          mitre           = [{ tactic = "Persistence", techniques = ["T1098"] }]
          entity_mappings = { accounts = [{ upn_column = "AccountUpn" }] }
        }
      }
    }
  }

  assert {
    condition     = length(msgraph_resource.detection_rules) == 2
    error_message = "One YAML file plus one HCL rule should deploy two rules."
  }

  assert {
    condition     = msgraph_resource.detection_rules["simple-signin-rule"].body.detectionAction.alertTemplate.entityMappings.accounts[0].upnColumn == "AccountUpn"
    error_message = "snake_case mapping attributes should normalise to Graph camelCase."
  }

  assert {
    condition     = msgraph_resource.detection_rules["simple-signin-rule"].body.detectionAction.alertTemplate.customDetails.SourceIp == "IPAddress"
    error_message = "custom_details keys pass through untouched (they are display names, not schema fields)."
  }

  assert {
    condition     = msgraph_resource.detection_rules["hcl-fixture"].body.detectionAction.alertTemplate.entityMappings.accounts[0].upnColumn == "AccountUpn"
    error_message = "HCL rules flow through the same normaliser as YAML files."
  }

  assert {
    condition     = output.rules["simple-signin-rule"].category == "identity" && output.rules["hcl-fixture"].category == "identity"
    error_message = "Category derives from the folder for files and the category attribute for HCL rules."
  }
}

run "sloppy_values_normalise" {
  command = plan

  variables {
    baseline_enabled = false
    custom_rules = {
      sloppy = {
        display_name = "Sloppy but salvageable"
        status       = "Enabled"
        frequency    = "pt1h"
        query        = "IdentityLogonEvents | project Timestamp, ReportId, AccountUpn"
        alert = {
          severity = "Medium"
          mitre = [
            { tactic = "credential access", techniques = ["t1110"] },
            { tactic = "DefenceEvasion", techniques = [{ technique = "t1562", sub_techniques = ["t1562.008"] }] },
          ]
          entity_mappings = { accounts = [{ upn_column = "AccountUpn" }] }
        }
      }
    }
  }

  assert {
    condition     = msgraph_resource.detection_rules["sloppy"].body.status == "enabled"
    error_message = "status should normalise to lowercase."
  }

  assert {
    condition     = msgraph_resource.detection_rules["sloppy"].body.schedule.frequency == "PT1H"
    error_message = "frequency should normalise to uppercase ISO 8601."
  }

  assert {
    condition     = msgraph_resource.detection_rules["sloppy"].body.detectionAction.alertTemplate.severity == "medium"
    error_message = "severity should normalise to lowercase."
  }

  assert {
    condition     = msgraph_resource.detection_rules["sloppy"].body.detectionAction.alertTemplate.tactics[0].tactic == "CredentialAccess"
    error_message = "A spaced lowercase tactic should canonicalise."
  }

  assert {
    condition     = length(msgraph_resource.detection_rules["sloppy"].body.detectionAction.alertTemplate.tactics) == 1
    error_message = "The body sends only the first tactic (live 400: only one tactic is currently supported)."
  }

  assert {
    condition     = msgraph_resource.detection_rules["sloppy"].body.detectionAction.alertTemplate.tactics[0].techniques[0].technique == "T1110"
    error_message = "Technique ids should uppercase."
  }

  assert {
    condition     = contains(output.rules["sloppy"].tactics, "DefenseEvasion")
    error_message = "Authoring keeps every tactic (British DefenceEvasion canonicalised) in the outputs even though the body sends one."
  }

  assert {
    condition     = contains(output.rules["sloppy"].techniques, "T1562.008")
    error_message = "Sub technique ids uppercase and roll into the outputs."
  }

  assert {
    condition     = contains(keys(output.mitre_coverage.tactics), "CredentialAccess") && contains(keys(output.mitre_coverage.techniques), "T1110")
    error_message = "Coverage outputs should roll up the canonical forms."
  }
}

run "invalid_files_fail_the_plan" {
  command = plan

  variables {
    baseline_enabled      = false
    custom_detections_dir = "tests/fixtures/invalid"
  }

  expect_failures = [terraform_data.schema_guard]
}

run "automated_actions_blocked_by_default" {
  command = plan

  variables {
    baseline_enabled      = false
    custom_detections_dir = "tests/fixtures/actions"
  }

  expect_failures = [terraform_data.schema_guard]
}

run "automated_actions_allowed_when_gated_open" {
  command = plan

  variables {
    baseline_enabled        = false
    custom_detections_dir   = "tests/fixtures/actions"
    allow_automated_actions = true
  }

  assert {
    condition     = msgraph_resource.detection_rules["rule-with-actions"].body.detectionAction.automatedActions.runAntivirusScans[0].deviceIdColumn == "DeviceId"
    error_message = "Automated actions should normalise to the Graph automatedActionSet shape."
  }

  assert {
    condition     = msgraph_resource.detection_rules["rule-with-actions"].body.detectionAction.automatedActions.isolateDevices[0].isolationType == "selective"
    error_message = "isolation_type should normalise to isolationType."
  }
}

# The retired-action detection must actually fire. A warning nobody has seen fire is a warning that
# may never fire, which is the failure mode this whole check exists to prevent, so it is asserted
# through the shared local rather than trusted. Delete this run with the keys on 2026-10-01.
run "retired_investigation_actions_are_detected" {
  command = plan

  variables {
    baseline_enabled        = false
    custom_detections_dir   = "tests/fixtures/retired-actions"
    allow_automated_actions = true
  }

  assert {
    condition     = output.rules_using_retired_actions == tolist(["tests/fixtures/retired-actions/endpoint/rule-with-retired-action.yaml"])
    error_message = "A rule using initiate_investigations should be reported in rules_using_retired_actions, which is what checks.tf warns on."
  }

  # The check is advisory in a real plan (a warning) but a failure in terraform test, so declaring it
  # here is what asserts it actually tripped rather than silently passing.
  expect_failures = [check.retired_investigation_actions]
}

run "clean_rules_report_no_retired_actions" {
  command = plan

  variables {
    baseline_enabled        = false
    custom_detections_dir   = "tests/fixtures/actions"
    allow_automated_actions = true
  }

  assert {
    condition     = length(output.rules_using_retired_actions) == 0
    error_message = "run_antivirus_scans and isolate_devices are not retiring, so they must not be reported."
  }
}

run "unknown_override_keys_fail" {
  command = plan

  variables {
    baseline_overrides = {
      no-such-rule                            = { status = "disabled" }
      legacy-authentication-successful-signin = { severty = "low" }
    }
  }

  expect_failures = [terraform_data.schema_guard]
}
