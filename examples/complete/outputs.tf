output "baseline_catalog_keys" {
  description = "Every baseline rule id (the keys baseline_overrides accepts)."
  value       = module.detection_rules.baseline_catalog_keys
}

output "ids_zipmap" {
  description = "Rule id to {name, id} for composition."
  value       = module.detection_rules.ids_zipmap
}

output "mitre_coverage" {
  description = "ATT&CK tactics and techniques mapped to the rules that cover them."
  value       = module.detection_rules.mitre_coverage
}

output "rules_by_category" {
  description = "Rule ids grouped by their analyst facing category."
  value       = module.detection_rules.rules_by_category
}
