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
