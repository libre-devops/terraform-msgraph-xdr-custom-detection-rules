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

# In-graph remote validation: each rule's query runs against the tenant's advanced hunting schema
# through the Graph runHuntingQuery action before the rule itself is created or updated, so a query
# that references a missing table or column fails the apply here, with the rule named, instead of
# at rule create. `| take 1` caps the result set (validation needs schema soundness, not data) and
# the response schema, the query's output columns, is tracked in state so column changes surface.
# A query change replaces its action, re-validating exactly when it matters. Gated by
# remote_query_validation because the applying principal needs ThreatHunting.Read.All.
resource "msgraph_resource_action" "validate_queries" {
  for_each = { for k, v in local.rule_bodies : k => v if var.remote_query_validation }

  resource_url = "security"
  action       = "runHuntingQuery"
  method       = "POST"
  api_version  = var.hunting_api_version

  body = {
    Query    = var.remote_validation_append_take ? "${each.value.queryCondition.queryText}\n| take 1" : each.value.queryCondition.queryText
    Timespan = var.remote_validation_timespan
  }

  response_export_values = {
    schema = "schema"
  }

  depends_on = [terraform_data.schema_guard]
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
