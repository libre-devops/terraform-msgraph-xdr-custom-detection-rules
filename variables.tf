variable "allow_automated_actions" {
  description = <<DESC
Gate for automated response actions. Automated actions run against real assets when a rule fires
(isolate a device, disable a user, quarantine a file, delete mail, and so on), so no rule from any
source (baseline, YAML directory, or custom_rules) may carry an automated_actions block until this
is explicitly set true. The plan fails, naming the offending files, when a rule declares actions
while the gate is off. Turning the gate on is a deliberate, reviewed decision for the calling stack.
DESC
  type        = bool
  default     = false
}

variable "allowed_frequencies" {
  description = <<DESC
The ISO 8601 durations a rule's `frequency` may use. Defaults to the schedules Defender XDR custom
detections support: every 1, 3, 12, or 24 hours (PT1H, PT3H, PT12H, PT24H, with P1D accepted as the
24 hour spelling) plus PT0S for Continuous (near real time). Narrow this list to enforce an
organisational floor (for example, forbid Continuous), or extend it if the service starts accepting
new schedules before this module catches up.
DESC
  type        = list(string)
  default     = ["PT0S", "PT1H", "PT3H", "PT12H", "PT24H", "P1D"]

  validation {
    condition     = length(var.allowed_frequencies) > 0 && alltrue([for f in var.allowed_frequencies : can(regex("^P", f))])
    error_message = "allowed_frequencies must be a non empty list of ISO 8601 durations (each starts with P, for example PT1H or P1D)."
  }
}

variable "api_version" {
  description = <<DESC
Microsoft Graph API version used for every detection rule call. Custom detection rules are
currently beta only, so the default is beta; flip to v1.0 when Microsoft promotes the API. Never
hardcoded so consumers are not pinned to this module's release cadence.
DESC
  type        = string
  default     = "beta"

  validation {
    condition     = contains(["beta", "v1.0"], var.api_version)
    error_message = "api_version must be beta or v1.0."
  }
}

variable "baseline_enabled" {
  description = <<DESC
Deploy the curated baseline detections shipped in this module's catalog/ directory (the same shape
as the policy module's baseline: calling the module gets a reviewed starter pack for free). Each
baseline rule is a YAML file under catalog/<category>/ and can be tuned or dropped per rule through
baseline_overrides. Set false to deploy only your own rules.
DESC
  type        = bool
  default     = true
}

variable "baseline_overrides" {
  description = <<DESC
Per rule tuning of the baseline, keyed by the baseline rule id (the id field in the catalog YAML,
which defaults to the file name; the baseline_catalog_keys output lists every key). Recognised
attributes per entry, all optional:

- enabled (bool): false drops the rule entirely.
- status (string): enabled or disabled, overriding the catalog value (deploy a rule in a disabled,
  tuning-mode state without forking the catalog).
- frequency (string): override the schedule (validated against allowed_frequencies).
- severity (string): override the alert severity.
- device_groups (list(string)): scope the rule to specific device groups.

Unknown keys, and keys that match no baseline rule, fail the plan.
DESC
  type        = any
  default     = {}

  validation {
    condition     = can({ for k, v in var.baseline_overrides : k => v })
    error_message = "baseline_overrides must be a map of objects keyed by baseline rule id."
  }
}

variable "custom_detections_dir" {
  description = <<DESC
Root directory of analyst authored detection rules, picked up per file: every *.yaml or *.yml under
<dir>/<category>/ becomes one custom detection rule, and the first level folder name is the rule's
category (its logical grouping for humans and for the mitre_coverage / rules_by_category outputs).
Files directly in the root land in the "uncategorised" category. Each file follows the schema in
schema/custom-detection.schema.json (every field is validated at plan time with the offending file
named). Null deploys no directory rules.
DESC
  type        = string
  default     = null
}

variable "custom_rules" {
  description = <<DESC
Detection rules authored directly in HCL, keyed by rule id, using exactly the same schema as the
YAML files (display_name, query, frequency, alert {severity, mitre, entity_mappings, ...},
device_groups, automated_actions, extra_body; a category attribute is also accepted since HCL rules
have no folder to derive it from). YAML files are the analyst path; this input exists for rules
that are generated or composed by the calling stack. Validated by the same engine as the files.
DESC
  type        = any
  default     = {}

  validation {
    condition     = can({ for k, v in var.custom_rules : k => v })
    error_message = "custom_rules must be a map of rule objects keyed by rule id."
  }
}

variable "id_prefix" {
  description = <<DESC
Optional prefix prepended to every rule id (baseline and custom), namespacing the rules this module
call owns, for example per environment or per stack ("soc-dev-"). The rule id is client provided on
create and doubles as the Terraform key, so the prefix keeps parallel deployments from colliding.
Null applies no prefix.
DESC
  type        = string
  default     = null

  validation {
    condition     = var.id_prefix == null || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.id_prefix))
    error_message = "id_prefix must start with a letter or digit and use only letters, digits, dots, underscores, or hyphens."
  }
}
