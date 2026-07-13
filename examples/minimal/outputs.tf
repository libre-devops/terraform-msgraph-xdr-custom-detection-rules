output "ids" {
  description = "Rule id to Graph detection rule id."
  value       = module.detection_rules.ids
}

output "rules" {
  description = "Metadata for the deployed rules."
  value       = module.detection_rules.rules
}
