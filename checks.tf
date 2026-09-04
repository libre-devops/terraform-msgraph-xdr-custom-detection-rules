# Advisory only: custom detections must return Timestamp and ReportId (plus an impacted entity
# column) or the service rejects the rule at create time. A rename projection can hide the columns
# from this simple token scan, so it warns instead of failing; the authoritative checks are the
# remote hunting-query validation in CI and the Graph create itself.
check "query_returns_required_columns" {
  assert {
    # Muted while schema violations exist: the guard already fails that plan with the real errors.
    condition = length(local.schema_violations) > 0 || alltrue([
      for k, r in local.rules :
      try(strcontains(tostring(r.raw.query), "Timestamp") && strcontains(tostring(r.raw.query), "ReportId"), true)
    ])
    error_message = "These rules do not visibly return the Timestamp and ReportId columns custom detections require (advisory; rename projections can hide them): ${join(", ", [for k, r in local.rules : r.file if !try(strcontains(tostring(r.raw.query), "Timestamp") && strcontains(tostring(r.raw.query), "ReportId"), true)])}"
  }
}

# Advisory only: a rule without a MITRE mapping still deploys, but it is invisible to the coverage
# outputs and the ATT&CK matrix the SOC reports on, which defeats detections as code hygiene.
check "rules_declare_mitre" {
  assert {
    # Muted while schema violations exist: the guard already fails that plan with the real errors.
    condition = length(local.schema_violations) > 0 || alltrue([
      for k, r in local.rules :
      try(length(r.raw.alert.mitre) > 0, false)
    ])
    error_message = "These rules declare no alert.mitre mapping, so they will not appear in MITRE coverage reporting (advisory): ${join(", ", [for k, r in local.rules : r.file if !try(length(r.raw.alert.mitre) > 0, false)])}"
  }
}

# Advisory only: Microsoft removes the two investigation response actions from the Graph security
# API on 1 OCTOBER 2026, as part of retiring standalone AIR (announced in MC1411577, effective
# 1 September 2026: AIR no longer runs as a separate investigation experience and standalone AIR
# investigation completion and auto-closure events no longer occur).
#
#   initiateInvestigations          removed 2026-10-01  ->  use run_antivirus_scans, or automatedAction
#   collectInvestigationPackages    removed 2026-10-01  ->  on detectionAction
#
# Warning rather than failing, because both still work up to that date and this module must not break
# a config that is currently valid. After it, the Graph create rejects them and this warning becomes
# the explanation for an otherwise opaque service error. run_antivirus_scans takes the same
# device_id_column shape, so a rule that used initiate_investigations for on-demand triage moves
# across with a key rename; there is no like-for-like replacement for the investigation package.
check "retired_investigation_actions" {
  assert {
    # Muted while schema violations exist: the guard already fails that plan with the real errors.
    condition     = length(local.schema_violations) > 0 || length(local.retired_action_rules) == 0
    error_message = "These rules use an investigation response action Microsoft removes from the Graph security API on 2026-10-01 (initiate_investigations / collect_investigation_packages, retired with standalone AIR): ${join(", ", local.retired_action_rules)}. Move initiate_investigations to run_antivirus_scans (same device_id_column shape); the investigation package has no like-for-like replacement."
  }
}
