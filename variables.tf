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

variable "hunting_api_version" {
  description = <<DESC
Microsoft Graph API version for the remote query validation calls (security/runHuntingQuery).
Defaults to v1.0, where the hunting API is generally available; independent of api_version because
the detection rule API and the hunting API promote separately.
DESC
  type        = string
  default     = "v1.0"

  validation {
    condition     = contains(["beta", "v1.0"], var.hunting_api_version)
    error_message = "hunting_api_version must be beta or v1.0."
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

variable "remote_query_validation" {
  description = <<DESC
Run every rule's KQL against the tenant through the Graph runHuntingQuery action inside the
Terraform graph, before the rule is created or updated. This proves tables and columns against the
real advanced hunting schema server side (queries run verbatim by default; see
remote_validation_append_take), and the response schema (the query's output columns) is tracked in
state. A query change replaces
its validation action, so re-validation happens exactly when a query changes. The applying
principal needs ThreatHunting.Read.All; set false to opt out (for example, a principal with only
CustomDetection.ReadWrite.All).
DESC
  type        = bool
  default     = true
}

variable "remote_validation_append_take" {
  description = <<DESC
Append a trailing "| take 1" to each remote validation query. Off by default on purpose: appending
an operator can interact badly with queries that already end in a take or limit, or whose final
operator matters, so the default runs every query verbatim and relies on the hunting endpoint's own
server side result caps. Enable it deliberately when your queries tolerate a trailing take and you
want validation to return as little data as possible.
DESC
  type        = bool
  default     = false
}

variable "remote_validation_timespan" {
  description = <<DESC
ISO 8601 timespan the remote validation queries look back over. Validation needs schema soundness,
not data, so the default PT1H keeps the scanned window (and the tenant load) minimal; widen it if
you want validation to double as a smoke test over real data.
DESC
  type        = string
  default     = "PT1H"

  validation {
    condition     = can(regex("^P", var.remote_validation_timespan)) || can(regex("^\\d{4}-", var.remote_validation_timespan))
    error_message = "remote_validation_timespan must be an ISO 8601 duration (PT1H, P1D) or timespan (start/duration or date forms)."
  }
}

variable "retry_error_message_regex" {
  description = <<DESC
Regular expressions the provider retries on when a Graph call fails, applied to the detection rule
resource and the validation actions. Transient service noise is retried by default; the provider
retries matching errors with backoff until the operation timeout bounds it (the provider exposes no
retry count knob, so the timeout is the ceiling). Set null to disable retries.
DESC
  type        = list(string)
  default     = ["(?i)too many requests", "(?i)service unavailable", "(?i)internal server error", "(?i)timeout", "(?i)temporarily unavailable"]
}

variable "timeouts" {
  description = <<DESC
Operation timeouts for the detection rule resource. Deletion is EVENTUALLY CONSISTENT server side
(proven live: the API accepts the delete, then the provider polls the read path, which can keep
returning the rule for many minutes; the portal shows the same lag), so the delete default is 30
minutes; deletes run in parallel, so a destroy shares one lag window rather than paying it per
rule. Transient errors retry per retry_error_message_regex.
DESC
  type = object({
    create = optional(string, "10m")
    delete = optional(string, "30m")
    read   = optional(string, "5m")
    update = optional(string, "10m")
  })
  default = {}
}
