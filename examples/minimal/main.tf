module "detection_rules" {
  source = "../.."

  # The smallest valid call: no curated baseline, one analyst authored rule picked up from the
  # custom-detections directory (one YAML file per rule, first level folder = category). The canary
  # rule matches nothing by construction, so a live apply creates a rule that never fires.
  baseline_enabled      = false
  custom_detections_dir = "${path.module}/custom-detections"
}
