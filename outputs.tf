output "baseline_catalog_keys" {
  description = "Every baseline rule id in this module's catalog (the keys baseline_overrides accepts), whether or not the baseline is enabled."
  value       = sort(local.baseline_ids)
}

output "ids" {
  description = "Map of rule id to the Graph detection rule id (client provided, so normally identical; kept as a map for composition symmetry with the estate)."
  value       = { for k, r in msgraph_resource.detection_rules : k => try(tostring(r.output.id), k) }
}

output "ids_zipmap" {
  description = "Map of rule id to {name, id} for easy composition, matching the estate wide zipmap convention."
  value       = { for k, r in msgraph_resource.detection_rules : k => { name = k, id = try(tostring(r.output.id), k) } }
}

output "mitre_coverage" {
  description = "ATT&CK coverage rolled up from the authored mitre blocks: tactics and techniques each map to the rule ids that cover them. Feeds the coverage report and workbooks."
  value = {
    tactics = {
      for t in distinct(flatten(values(local.rule_tactics))) :
      t => sort([for k, ts in local.rule_tactics : k if contains(ts, t)])
    }
    techniques = {
      for t in distinct(flatten(values(local.rule_techniques))) :
      t => sort([for k, ts in local.rule_techniques : k if contains(ts, t)])
    }
  }
}

output "rules" {
  description = "Metadata for every deployed rule: display name, category, source (baseline, custom_detections_dir, or custom_rules), the file it came from, status, schedule, severity, and its MITRE tactics and techniques."
  value = {
    for k, r in local.rules : k => {
      category     = r.category
      display_name = try(tostring(r.raw.display_name), k)
      file         = r.file
      frequency    = try(upper(tostring(r.raw.frequency)), null)
      severity     = try(lower(tostring(r.raw.alert.severity)), null)
      source       = r.source
      status       = try(lower(tostring(r.raw.status)), "enabled")
      tactics      = local.rule_tactics[k]
      techniques   = local.rule_techniques[k]
    }
  }
}

output "rules_by_category" {
  description = "Rule ids grouped by category (the analyst facing logical separation: the first level folder for file rules, the category attribute or \"custom\" for HCL rules)."
  value = {
    for c in distinct([for k, r in local.rules : r.category]) :
    c => sort([for k, r in local.rules : k if r.category == c])
  }
}

output "rules_using_retired_actions" {
  description = "Files of any rule still using an investigation response action Microsoft removes from the Graph security API on 2026-10-01 (initiate_investigations, collect_investigation_packages). Empty is the healthy state; surface it in a calling stack to track the migration. checks.tf warns on the same list."
  value       = local.retired_action_rules
}
