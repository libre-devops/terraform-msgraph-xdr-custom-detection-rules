# The schema guard: one place where every validation message from the pipeline in locals.tf fails
# the plan together, so an analyst sees every problem across every file in a single run instead of
# fixing them one apply at a time.
resource "terraform_data" "schema_guard" {
  lifecycle {
    precondition {
      condition     = length(local.schema_violations) == 0
      error_message = "${length(local.schema_violations)} detection rule schema problem(s):\n  - ${join("\n  - ", local.schema_violations)}"
    }
  }
}

# One Graph custom detection rule per validated rule, from every source (baseline catalog, the
# analyst YAML directory, and custom_rules). The rule id is client provided (it doubles as the
# for_each key, so plans stay stable and re-creates never collide), and updates PATCH the existing
# rule in place.
resource "msgraph_resource" "detection_rules" {
  for_each = local.rule_bodies

  url           = "security/rules/detectionRules"
  api_version   = var.api_version
  body          = each.value
  update_method = "PATCH"

  response_export_values = {
    id           = "id"
    display_name = "displayName"
    status       = "status"
  }

  depends_on = [terraform_data.schema_guard]
}

# MITRE roll ups for the coverage outputs (and the CI coverage report), read straight from the
# authored mitre blocks rather than the deployed rules so a plan can report coverage too.
locals {
  rule_tactics = {
    for k, r in local.rules : k => distinct([
      for m in try(concat(r.raw.alert.mitre, []), []) : try(tostring(m.tactic), "unknown")
    ])
  }

  rule_techniques = {
    for k, r in local.rules : k => distinct(flatten([
      for m in try(concat(r.raw.alert.mitre, []), []) : [
        for t in try(concat(m.techniques, []), []) :
        can(tostring(t)) ? [tostring(t)] : concat([try(tostring(t.technique), "unknown")], try(concat(t.sub_techniques, []), []))
      ]
    ]))
  }
}
