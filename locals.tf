# -------------------------------------------------------------------------------------------------
# The rule pipeline: gather YAML files and HCL rules, validate every field against the Graph
# detectionRule schema, and normalise the analyst friendly snake_case shape into the Graph camelCase
# request body. The allowed key sets and enums below are extracted from the Graph beta $metadata
# (microsoft.graph.security namespace) and are the single source of truth for both the validator and
# the normaliser; schema/custom-detection.schema.json mirrors them for editors and CI.
#
# The module builds on the current schema only: status (not the deprecated isEnabled), tactics with
# nested techniques (not the deprecated category/mitreTechniques), entityMappings (not the
# deprecated impactedAssets) and automatedActions (not the deprecated responseActions). The
# deprecated forms are removed from the API on 2026-10-01.
# -------------------------------------------------------------------------------------------------

locals {
  # ---- allowed shapes (snake_case, the authoring schema) ----------------------------------------
  alert_keys     = ["title", "description", "severity", "recommended_actions", "mitre", "custom_details", "entity_mappings"]
  mitre_keys     = ["tactic", "techniques"]
  rule_top_keys  = ["id", "category", "display_name", "description", "status", "frequency", "query", "alert", "device_groups", "automated_actions", "extra_body"]
  technique_keys = ["technique", "sub_techniques"]

  isolation_types = ["full", "selective"]
  severities      = ["informational", "low", "medium", "high"]
  statuses        = ["enabled", "disabled"]

  # MITRE ATT&CK enterprise tactics, in the spelling the Graph API uses.
  tactics = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "CommandAndControl", "Exfiltration", "Impact",
  ]

  sub_technique_pattern = "^T\\d{4}\\.\\d{3}$"
  technique_pattern     = "^T\\d{4}(\\.\\d{3})?$"

  # Entity mapping groups and their columns (entityMappingConfiguration and the 17 entityMapping
  # types in $metadata). Keys here are the YAML attribute names; the graph name maps translate them.
  entity_mapping_keys = {
    accounts               = ["aad_user_id_column", "dns_domain_column", "name_column", "nt_domain_column", "sid_column", "upn_column", "upn_suffix_column"]
    amazon_resources       = ["amazon_resource_id_column"]
    azure_resources        = ["resource_id_column"]
    cloud_applications     = ["app_id_column", "name_column"]
    dns                    = ["domain_name_column", "host_ip_address_column", "server_ip_column"]
    files                  = ["name_column", "sha1_column", "sha256_column"]
    google_cloud_resources = ["full_resource_name_column"]
    hosts                  = ["device_id_column", "dns_domain_column", "name_column", "net_bios_name_column", "nt_domain_column"]
    ips                    = ["address_column", "scope_column"]
    mail_clusters          = ["query_column", "source_column"]
    mail_messages          = ["network_message_id_column", "recipient_column", "sender_column", "subject_column"]
    mailboxes              = ["primary_address_column"]
    oauth_applications     = ["oauth_app_id_column"]
    processes              = ["sha1_column", "sha256_column"]
    registry_values        = ["key_column", "value_name_column"]
    security_groups        = ["distinguished_name_column", "object_id_column", "sid_column"]
    urls                   = ["address_column"]
  }

  entity_mapping_graph_names = {
    accounts               = "accounts"
    amazon_resources       = "amazonResources"
    azure_resources        = "azureResources"
    cloud_applications     = "cloudApplications"
    dns                    = "dns"
    files                  = "files"
    google_cloud_resources = "googleCloudResources"
    hosts                  = "hosts"
    ips                    = "ips"
    mail_clusters          = "mailClusters"
    mail_messages          = "mailMessages"
    mailboxes              = "mailboxes"
    oauth_applications     = "oAuthApplications"
    processes              = "processes"
    registry_values        = "registryValues"
    security_groups        = "securityGroups"
    urls                   = "urls"
  }

  # Automated response actions and their attributes (automatedActionSet in $metadata). Every action
  # here acts on real assets when the rule fires, which is why allow_automated_actions gates them.
  automated_action_keys = {
    allow_files                    = ["sha1_column", "sha256_column", "device_group_names"]
    block_files                    = ["sha1_column", "sha256_column", "device_group_names"]
    collect_investigation_packages = ["device_id_column"]
    disable_users                  = ["account_sid_column"]
    force_user_password_resets     = ["account_sid_column"]
    hard_delete_emails             = ["network_message_id_column", "recipient_column"]
    initiate_investigations        = ["device_id_column"]
    isolate_devices                = ["device_id_column", "isolation_type"]
    mark_users_as_compromised      = ["account_object_id_column"]
    move_emails_to_deleted_items   = ["network_message_id_column", "recipient_column"]
    move_emails_to_inbox           = ["network_message_id_column", "recipient_column"]
    move_emails_to_junk            = ["network_message_id_column", "recipient_column"]
    restrict_app_executions        = ["device_id_column"]
    run_antivirus_scans            = ["device_id_column"]
    soft_delete_emails             = ["network_message_id_column", "recipient_column"]
    stop_and_quarantine_files      = ["device_id_column", "sha1_column"]
  }

  automated_action_graph_names = {
    allow_files                    = "allowFiles"
    block_files                    = "blockFiles"
    collect_investigation_packages = "collectInvestigationPackages"
    disable_users                  = "disableUsers"
    force_user_password_resets     = "forceUserPasswordResets"
    hard_delete_emails             = "hardDeleteEmails"
    initiate_investigations        = "initiateInvestigations"
    isolate_devices                = "isolateDevices"
    mark_users_as_compromised      = "markUsersAsCompromised"
    move_emails_to_deleted_items   = "moveEmailsToDeletedItems"
    move_emails_to_inbox           = "moveEmailsToInbox"
    move_emails_to_junk            = "moveEmailsToJunk"
    restrict_app_executions        = "restrictAppExecutions"
    run_antivirus_scans            = "runAntivirusScans"
    soft_delete_emails             = "softDeleteEmails"
    stop_and_quarantine_files      = "stopAndQuarantineFiles"
  }

  override_keys = ["enabled", "status", "frequency", "severity", "device_groups"]

  # Attribute names whose generic snake_case to camelCase conversion would be wrong.
  camel_overrides = { oauth_app_id_column = "oAuthAppIdColumn" }

  # Value normalisation, best endeavours for analyst input: KEYS are strict (they are the schema
  # contract and editors autocomplete them), VALUES are forgiving. status, severity and isolation
  # types compare and emit lowercased; frequencies and technique ids uppercased (pt1h, t1110);
  # tactics resolve case and separator insensitively through this map (credential access,
  # credential-access and CredentialAccess all canonicalise, and the British DefenceEvasion maps to
  # the API's DefenseEvasion). Unknown values still fail the plan with the canonical list named.
  tactic_canonical = {
    collection          = "Collection"
    commandandcontrol   = "CommandAndControl"
    credentialaccess    = "CredentialAccess"
    defenceevasion      = "DefenseEvasion"
    defenseevasion      = "DefenseEvasion"
    discovery           = "Discovery"
    execution           = "Execution"
    exfiltration        = "Exfiltration"
    impact              = "Impact"
    initialaccess       = "InitialAccess"
    lateralmovement     = "LateralMovement"
    persistence         = "Persistence"
    privilegeescalation = "PrivilegeEscalation"
    reconnaissance      = "Reconnaissance"
    resourcedevelopment = "ResourceDevelopment"
  }
}

# -------------------------------------------------------------------------------------------------
# Gather: baseline catalog files, analyst directory files, and HCL rules, each carried with its
# provenance (file) so every validation message names the offending source.
# -------------------------------------------------------------------------------------------------
locals {
  baseline_files = fileset("${path.module}/catalog", "**/*.{yaml,yml}")
  custom_files   = var.custom_detections_dir != null ? fileset(var.custom_detections_dir, "**/*.{yaml,yml}") : toset([])

  baseline_entries_all = [
    for f in sort(local.baseline_files) : {
      source   = "baseline"
      file     = "catalog/${f}"
      category = length(split("/", f)) > 1 ? split("/", f)[0] : "uncategorised"
      slug     = replace(basename(f), "/\\.(yaml|yml)$/", "")
      raw      = try(yamldecode(file("${path.module}/catalog/${f}")), "__YAML_PARSE_ERROR__")
    }
  ]

  custom_file_entries_all = [
    for f in sort(local.custom_files) : {
      source   = "custom_detections_dir"
      file     = "${var.custom_detections_dir}/${f}"
      category = length(split("/", f)) > 1 ? split("/", f)[0] : "uncategorised"
      slug     = replace(basename(f), "/\\.(yaml|yml)$/", "")
      raw      = try(yamldecode(file("${var.custom_detections_dir}/${f}")), "__YAML_PARSE_ERROR__")
    }
  ]

  # The un-prefixed id: an explicit id field wins, else the file name. baseline_overrides key on it.
  baseline_keyed_all = [
    for e in local.baseline_entries_all : merge(e, {
      base_key = can(keys(e.raw)) ? coalesce(try(tostring(e.raw.id), null), e.slug) : e.slug
    })
  ]

  baseline_ids = [for e in local.baseline_keyed_all : e.base_key]

  # Apply overrides (tunable fields merged over the catalog values) and drop enabled = false rules;
  # baseline_enabled = false drops the whole set.
  baseline_keyed = [
    for e in local.baseline_keyed_all : merge(e, {
      # try() instead of a ternary: the merged object gains attributes the unmerged one lacks, which
      # a conditional cannot type-unify; merge() on the parse error sentinel throws and falls back.
      # status, frequency and device_groups override at the top level; severity lives under alert.
      raw = try(
        merge(
          e.raw,
          { for ok, ov in try(var.baseline_overrides[e.base_key], {}) : ok => ov if contains(["status", "frequency", "device_groups"], ok) },
          { for ok, ov in try(var.baseline_overrides[e.base_key], {}) : "alert" => merge(e.raw.alert, { severity = ov }) if ok == "severity" },
        ),
        e.raw,
      )
    }) if var.baseline_enabled && try(var.baseline_overrides[e.base_key].enabled, true) != false
  ]

  custom_file_keyed = [
    for e in local.custom_file_entries_all : merge(e, {
      base_key = can(keys(e.raw)) ? coalesce(try(tostring(e.raw.id), null), e.slug) : e.slug
    })
  ]

  hcl_entries = [
    for k in sort(keys(var.custom_rules)) : {
      source   = "custom_rules"
      file     = format("custom_rules[%q]", k)
      category = "custom"
      slug     = k
      base_key = k
      raw      = var.custom_rules[k]
    }
  ]

  # Every rule from every source, with its final (prefixed) id and effective category.
  keyed_entries = [
    for e in concat(local.baseline_keyed, local.custom_file_keyed, local.hcl_entries) : merge(e, {
      key      = "${var.id_prefix != null ? var.id_prefix : ""}${e.base_key}"
      category = can(keys(e.raw)) ? coalesce(try(tostring(e.raw.category), null), e.category) : e.category
      valid    = can(keys(e.raw))
    })
  ]

  # Group by id so duplicates are reported instead of crashing a map comprehension; the deduped map
  # drives the detailed validation and the resource for_each.
  grouped_entries = { for e in local.keyed_entries : e.key => e... }
  rules           = { for k, v in local.grouped_entries : k => v[0] }
}

# -------------------------------------------------------------------------------------------------
# Validate: every family of checks appends messages that name the offending file and field. Any
# message fails the plan through the schema guard in main.tf. Detailed families run over the
# deduped map; parse, duplicate and top level families run over every entry.
# -------------------------------------------------------------------------------------------------
locals {
  v_parse = [for e in local.keyed_entries : "${e.file}: not readable as a YAML mapping (parse error, or the document is not a mapping)" if !e.valid]

  v_duplicates = [
    for k, v in local.grouped_entries :
    "rule id ${k}: defined ${length(v)} times (${join(", ", [for e in v : e.file])}); rule ids must be unique across the baseline, the directory and custom_rules"
    if length(v) > 1
  ]

  v_top_keys = flatten([
    for e in local.keyed_entries : [
      for uk in(e.valid ? setsubtract(keys(e.raw), local.rule_top_keys) : []) :
      "${e.file}: unknown attribute ${uk} (allowed: ${join(", ", local.rule_top_keys)})"
    ]
  ])

  v_required = flatten([
    for e in local.keyed_entries : [
      for rk in ["display_name", "query", "frequency", "alert"] :
      "${e.file}: required attribute ${rk} is missing"
      if e.valid && !try(contains(keys(e.raw), rk), true)
    ]
  ])

  v_hcl_id = [
    for e in local.keyed_entries :
    "${e.file}: do not set id on custom_rules entries (the map key is the rule id)"
    if e.valid && e.source == "custom_rules" && try(contains(keys(e.raw), "id"), false)
  ]

  v_key_format = [
    for e in local.keyed_entries :
    "${e.file}: rule id ${e.key} is invalid (start with a letter or digit; letters, digits, dots, underscores and hyphens only; 128 characters maximum)"
    if !can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", e.key))
  ]

  v_display_name = [
    for k, r in local.rules :
    "${r.file}: display_name must be a non empty string"
    if r.valid && try(contains(keys(r.raw), "display_name"), false) && trimspace(try(tostring(r.raw.display_name), "")) == ""
  ]

  v_status = [
    for k, r in local.rules :
    "${r.file}: status ${try(tostring(r.raw.status), "(not a string)")} is invalid (allowed: ${join(", ", local.statuses)})"
    if r.valid && try(contains(keys(r.raw), "status"), false) && !contains(local.statuses, try(lower(tostring(r.raw.status)), ""))
  ]

  v_frequency = [
    for k, r in local.rules :
    "${r.file}: frequency ${try(tostring(r.raw.frequency), "(not a string)")} is not in allowed_frequencies (${join(", ", var.allowed_frequencies)})"
    if r.valid && try(contains(keys(r.raw), "frequency"), false) && !contains([for f in var.allowed_frequencies : upper(f)], try(upper(tostring(r.raw.frequency)), ""))
  ]

  v_query = [
    for k, r in local.rules :
    "${r.file}: query must be a non empty string of KQL"
    if r.valid && try(contains(keys(r.raw), "query"), false) && trimspace(try(tostring(r.raw.query), "")) == ""
  ]

  v_device_groups = flatten([
    for k, r in local.rules : (
      r.valid && try(contains(keys(r.raw), "device_groups"), false) ? (
        can(concat(r.raw.device_groups, [])) ? [
          for dg in r.raw.device_groups :
          "${r.file}: device_groups entries must be non empty strings"
          if trimspace(try(tostring(dg), "")) == ""
        ] : ["${r.file}: device_groups must be a list of device group names"]
      ) : []
    )
  ])

  # ---- alert block ----
  v_alert = flatten([
    for k, r in local.rules : (
      r.valid && try(contains(keys(r.raw), "alert"), false) ? (
        can(keys(r.raw.alert)) ? concat(
          [
            for uk in setsubtract(keys(r.raw.alert), local.alert_keys) :
            "${r.file}: unknown alert attribute ${uk} (allowed: ${join(", ", local.alert_keys)})"
          ],
          contains(keys(r.raw.alert), "severity") ? (
            contains(local.severities, try(lower(tostring(r.raw.alert.severity)), "")) ? [] :
            ["${r.file}: alert.severity ${try(tostring(r.raw.alert.severity), "(not a string)")} is invalid (allowed: ${join(", ", local.severities)})"]
          ) : ["${r.file}: required attribute alert.severity is missing"],
          contains(keys(r.raw.alert), "custom_details") ? (
            can(keys(r.raw.alert.custom_details)) ? [
              for dk, dv in r.raw.alert.custom_details :
              "${r.file}: alert.custom_details ${dk} must name a non empty query column"
              if trimspace(try(tostring(dv), "")) == ""
            ] : ["${r.file}: alert.custom_details must be a mapping of detail name to query column"]
          ) : [],
        ) : ["${r.file}: alert must be a mapping"]
      ) : []
    )
  ])

  # ---- MITRE mapping ----
  v_mitre = flatten([
    for k, r in local.rules : (
      try(contains(keys(r.raw.alert), "mitre"), false) ? (
        can(concat(r.raw.alert.mitre, [])) ? [
          for m in r.raw.alert.mitre : (
            can(keys(m)) ? concat(
              [
                for uk in setsubtract(keys(m), local.mitre_keys) :
                "${r.file}: unknown mitre attribute ${uk} (allowed: ${join(", ", local.mitre_keys)})"
              ],
              contains(keys(m), "tactic") ? (
                contains(keys(local.tactic_canonical), replace(lower(try(tostring(m.tactic), "?")), "/[ _-]/", "")) ? [] :
                ["${r.file}: mitre tactic ${try(tostring(m.tactic), "(not a string)")} is not a MITRE ATT&CK enterprise tactic (allowed: ${join(", ", local.tactics)})"]
              ) : ["${r.file}: every mitre entry needs a tactic"],
              contains(keys(m), "techniques") ? (
                can(concat(m.techniques, [])) ? flatten([
                  for t in m.techniques : (
                    can(tostring(t)) ? (
                      can(regex(local.technique_pattern, upper(tostring(t)))) ? [] :
                      ["${r.file}: technique ${tostring(t)} must look like T1059 or T1059.001"]
                      ) : (
                      can(keys(t)) ? concat(
                        [
                          for uk in setsubtract(keys(t), local.technique_keys) :
                          "${r.file}: unknown technique attribute ${uk} (allowed: ${join(", ", local.technique_keys)})"
                        ],
                        can(regex(local.technique_pattern, try(upper(tostring(t.technique)), ""))) ? [] :
                        ["${r.file}: technique ${try(tostring(t.technique), "(missing)")} must look like T1059 or T1059.001"],
                        contains(keys(t), "sub_techniques") ? (
                          can(concat(t.sub_techniques, [])) ? [
                            for st in t.sub_techniques :
                            "${r.file}: sub technique ${try(tostring(st), "(not a string)")} must look like T1059.001"
                            if !can(regex(local.sub_technique_pattern, try(upper(tostring(st)), "")))
                          ] : ["${r.file}: sub_techniques must be a list"]
                        ) : [],
                      ) : ["${r.file}: techniques entries must be strings or mappings"]
                    )
                  )
                ]) : ["${r.file}: techniques must be a list"]
              ) : [],
            ) : ["${r.file}: mitre entries must be mappings"]
          )
        ] : [["${r.file}: alert.mitre must be a list of tactic mappings"]]
      ) : []
    )
  ])

  # ---- entity mappings ----
  v_entity_mappings = flatten([
    for k, r in local.rules : (
      try(contains(keys(r.raw.alert), "entity_mappings"), false) ? (
        can(keys(r.raw.alert.entity_mappings)) ? concat(
          [
            for uk in setsubtract(keys(r.raw.alert.entity_mappings), keys(local.entity_mapping_keys)) :
            "${r.file}: unknown entity mapping group ${uk} (allowed: ${join(", ", sort(keys(local.entity_mapping_keys)))})"
          ],
          flatten([
            for g, items in r.raw.alert.entity_mappings : (
              contains(keys(local.entity_mapping_keys), g) ? (
                can(concat(items, [])) ? flatten([
                  for it in items : (
                    can(keys(it)) ? concat(
                      [
                        for uk in setsubtract(keys(it), local.entity_mapping_keys[g]) :
                        "${r.file}: unknown ${g} mapping attribute ${uk} (allowed: ${join(", ", local.entity_mapping_keys[g])})"
                      ],
                      [
                        for ck, cv in it :
                        "${r.file}: ${g} mapping attribute ${ck} must name a non empty query column"
                        if trimspace(try(tostring(cv), "")) == ""
                      ],
                    ) : ["${r.file}: ${g} mappings must be a list of mappings"]
                  )
                ]) : ["${r.file}: entity mapping group ${g} must be a list"]
              ) : []
            )
          ]),
        ) : ["${r.file}: alert.entity_mappings must be a mapping of entity groups"]
      ) : []
    )
  ])

  # Live 400 (InvalidInput): "Entity mapping for 'MailMessage' is invalid. At least one mandatory
  # field combination must have non-empty column values." The proven good shape maps network
  # message id, recipient and sender together (the four column baseline rule created clean; a
  # network id plus recipient pair was rejected).
  v_mail_message_combo = flatten([
    for k, r in local.rules : [
      for it in try(concat(r.raw.alert.entity_mappings.mail_messages, []), []) :
      "${r.file}: mail_messages mappings must set network_message_id_column, recipient_column and sender_column together (the API rejects lesser combinations; subject_column is recommended too)"
      if can(keys(it)) && length(setsubtract(["network_message_id_column", "recipient_column", "sender_column"], keys(it))) > 0
    ]
  ])

  # Live 400 (BadRequest): "At least one asset entity (Machine, User, or Mailbox) or an IP entity
  # must be included." Every rule must map at least one asset from the query results.
  v_asset_entity = [
    for k, r in local.rules :
    "${r.file}: at least one asset entity mapping is required (accounts, hosts, mailboxes, or ips); related evidence entities like mail_messages or files are not enough for the API"
    if r.valid && length(setintersection(["accounts", "hosts", "mailboxes", "ips"], keys(can(keys(try(r.raw.alert.entity_mappings, 0))) ? r.raw.alert.entity_mappings : {}))) == 0
  ]

  # Product documented caps: 20 custom detail pairs per rule, and up to three {{Column}} dynamic
  # references in each of the alert title and description.
  v_custom_details_cap = [
    for k, r in local.rules :
    "${r.file}: alert.custom_details carries ${length(try(r.raw.alert.custom_details, {}))} pairs; the service caps a rule at 20"
    if r.valid && can(keys(try(r.raw.alert.custom_details, 0))) && length(r.raw.alert.custom_details) > 20
  ]

  v_dynamic_refs = concat(
    [
      for k, r in local.rules :
      "${r.file}: alert.title references more than three columns with {{ }}; the service supports up to three per field"
      if r.valid && length(regexall("\\{\\{", try(tostring(r.raw.alert.title), ""))) > 3
    ],
    [
      for k, r in local.rules :
      "${r.file}: alert.description references more than three columns with {{ }}; the service supports up to three per field"
      if r.valid && length(regexall("\\{\\{", try(tostring(r.raw.alert.description), ""))) > 3
    ],
  )

  # Continuous (NRT) rules run under documented restrictions: one table, no joins, unions or
  # externaldata, and no comment lines, against a supported table allow-list.
  nrt_supported_tables = [
    "AlertEvidence", "CloudAppEvents", "DeviceEvents", "DeviceFileCertificateInfo",
    "DeviceFileEvents", "DeviceImageLoadEvents", "DeviceLogonEvents", "DeviceNetworkEvents",
    "DeviceNetworkInfo", "DeviceInfo", "DeviceProcessEvents", "DeviceRegistryEvents",
    "EmailAttachmentInfo", "EmailEvents", "EmailPostDeliveryEvents", "EmailUrlInfo",
    "IdentityDirectoryEvents", "IdentityLogonEvents", "IdentityQueryEvents", "UrlClickEvents",
    "AuditLogs", "AWSCloudTrail", "AWSGuardDuty", "AzureActivity", "CommonSecurityLog",
    "GCPAuditLogs", "MicrosoftGraphActivityLogs", "OfficeActivity", "ProofpointPOD",
    "SecurityAlert", "SecurityEvent", "SigninLogs",
  ]

  v_nrt = flatten([
    for k, r in local.rules : (
      r.valid && try(upper(tostring(r.raw.frequency)), "") == "PT0S" ? concat(
        length(regexall("(?i)\\bjoin\\b|\\bunion\\b|externaldata", try(tostring(r.raw.query), ""))) > 0 ?
        ["${r.file}: Continuous (NRT) queries must not use join, union, or externaldata"] : [],
        length(regexall("//", try(tostring(r.raw.query), ""))) > 0 ?
        ["${r.file}: Continuous (NRT) queries must not contain comment lines"] : [],
        contains(local.nrt_supported_tables, try(trimspace(split("|", tostring(r.raw.query))[0]), "")) ? [] :
        ["${r.file}: Continuous (NRT) supports a fixed table list, and '${try(trimspace(split("|", tostring(r.raw.query))[0]), "?")}' is not on it (see the docs; use an hourly schedule instead)"],
      ) : []
    )
  ])

  # ---- automated actions (destructive, gated) ----
  v_actions_gate = var.allow_automated_actions ? [] : [
    for k, r in local.rules :
    "${r.file}: declares automated_actions but allow_automated_actions is false on this module call; automated response actions act on real assets and are a deliberate opt in"
    if r.valid && try(contains(keys(r.raw), "automated_actions"), false)
  ]

  v_automated_actions = flatten([
    for k, r in local.rules : (
      r.valid && try(contains(keys(r.raw), "automated_actions"), false) ? (
        can(keys(r.raw.automated_actions)) ? concat(
          [
            for uk in setsubtract(keys(r.raw.automated_actions), keys(local.automated_action_keys)) :
            "${r.file}: unknown automated action ${uk} (allowed: ${join(", ", sort(keys(local.automated_action_keys)))})"
          ],
          flatten([
            for g, items in r.raw.automated_actions : (
              contains(keys(local.automated_action_keys), g) ? (
                can(concat(items, [])) ? flatten([
                  for it in items : (
                    can(keys(it)) ? concat(
                      [
                        for uk in setsubtract(keys(it), local.automated_action_keys[g]) :
                        "${r.file}: unknown ${g} attribute ${uk} (allowed: ${join(", ", local.automated_action_keys[g])})"
                      ],
                      [
                        for ck, cv in it :
                        "${r.file}: ${g} attribute ${ck} must name a non empty query column"
                        if ck != "device_group_names" && ck != "isolation_type" && trimspace(try(tostring(cv), "")) == ""
                      ],
                      contains(keys(it), "isolation_type") && !contains(local.isolation_types, try(lower(tostring(it.isolation_type)), "")) ?
                      ["${r.file}: ${g} isolation_type ${try(tostring(it.isolation_type), "(not a string)")} is invalid (allowed: ${join(", ", local.isolation_types)})"] : [],
                      contains(keys(it), "device_group_names") && !can(concat(it.device_group_names, [])) ?
                      ["${r.file}: ${g} device_group_names must be a list of device group names"] : [],
                    ) : ["${r.file}: ${g} entries must be mappings"]
                  )
                ]) : ["${r.file}: automated action ${g} must be a list"]
              ) : []
            )
          ]),
        ) : ["${r.file}: automated_actions must be a mapping of action groups"]
      ) : []
    )
  ])

  # ---- baseline overrides ----
  v_overrides = flatten([
    for ok, ov in var.baseline_overrides : concat(
      contains(local.baseline_ids, ok) ? [] : ["baseline_overrides[${ok}]: no baseline rule has this id (the baseline_catalog_keys output lists them)"],
      var.baseline_enabled ? [] : ["baseline_overrides[${ok}]: baseline_enabled is false, so overrides have no effect; remove them or re-enable the baseline"],
      can(keys(ov)) ? concat(
        [
          for uk in setsubtract(keys(ov), local.override_keys) :
          "baseline_overrides[${ok}]: unknown attribute ${uk} (allowed: ${join(", ", local.override_keys)})"
        ],
        contains(keys(ov), "status") && !contains(local.statuses, try(lower(tostring(ov.status)), "")) ?
        ["baseline_overrides[${ok}]: status must be one of ${join(", ", local.statuses)}"] : [],
        contains(keys(ov), "frequency") && !contains([for f in var.allowed_frequencies : upper(f)], try(upper(tostring(ov.frequency)), "")) ?
        ["baseline_overrides[${ok}]: frequency must be in allowed_frequencies (${join(", ", var.allowed_frequencies)})"] : [],
        contains(keys(ov), "severity") && !contains(local.severities, try(lower(tostring(ov.severity)), "")) ?
        ["baseline_overrides[${ok}]: severity must be one of ${join(", ", local.severities)}"] : [],
      ) : ["baseline_overrides[${ok}]: must be a mapping"],
    )
  ])

  schema_violations = sort(concat(
    local.v_parse, local.v_duplicates, local.v_top_keys, local.v_required, local.v_hcl_id,
    local.v_key_format, local.v_display_name, local.v_status, local.v_frequency, local.v_query,
    local.v_device_groups, local.v_alert, local.v_mitre, local.v_entity_mappings,
    local.v_mail_message_combo, local.v_asset_entity, local.v_custom_details_cap,
    local.v_dynamic_refs, local.v_nrt, local.v_actions_gate, local.v_automated_actions,
    local.v_overrides,
  ))
}

# -------------------------------------------------------------------------------------------------
# Normalise: snake_case authoring shape to the Graph camelCase body. Every access is guarded with
# try() so a rule that failed validation never crashes evaluation; the schema guard fails the plan
# with the real message instead. Column attributes convert generically (sha1_column to sha1Column),
# with camel_overrides for the names the generic rule would get wrong.
# -------------------------------------------------------------------------------------------------
locals {
  # Techniques normalise in two filtered passes (bare strings, then mappings) because a single
  # ternary cannot unify the two shapes into one type.
  norm_mitre = {
    for k, r in local.rules : k => [
      for m in try(concat(r.raw.alert.mitre, []), []) : merge(
        { tactic = lookup(local.tactic_canonical, replace(lower(try(tostring(m.tactic), "unknown")), "/[ _-]/", ""), try(tostring(m.tactic), "unknown")) },
        {
          techniques = concat(
            [
              for t in try(concat(m.techniques, []), []) :
              { technique = upper(tostring(t)) } if can(tostring(t))
            ],
            [
              for t in try(concat(m.techniques, []), []) :
              merge(
                { technique = try(upper(tostring(t.technique)), "unknown") },
                try(length(t.sub_techniques) > 0, false) ? { subTechniques = [for st in try(concat(t.sub_techniques, []), []) : try(upper(tostring(st)), "unknown")] } : {},
              ) if !can(tostring(t))
            ],
          )
        },
      )
    ] if r.valid
  }

  norm_entity_mappings = {
    for k, r in local.rules : k => {
      for g, items in(can(keys(try(r.raw.alert.entity_mappings, 0))) ? r.raw.alert.entity_mappings : {}) :
      lookup(local.entity_mapping_graph_names, g, g) => [
        for it in try(concat(items, []), []) : {
          for ck, cv in(can(keys(it)) ? it : {}) :
          lookup(local.camel_overrides, ck, join("", [for i, p in split("_", ck) : i == 0 ? p : title(p)])) => cv
        }
      ]
    } if r.valid
  }

  # isolation_type merges separately (lowercased) because a ternary over the mixed value types the
  # generic pass carries (strings and the device_group_names list) cannot type-unify.
  norm_automated_actions = {
    for k, r in local.rules : k => {
      for g, items in(can(keys(try(r.raw.automated_actions, 0))) ? r.raw.automated_actions : {}) :
      lookup(local.automated_action_graph_names, g, g) => [
        for it in try(concat(items, []), []) : merge(
          {
            for ck, cv in(can(keys(it)) ? it : {}) :
            lookup(local.camel_overrides, ck, join("", [for i, p in split("_", ck) : i == 0 ? p : title(p)])) => cv
            if ck != "isolation_type"
          },
          {
            for ck, cv in(can(keys(it)) ? it : {}) :
            "isolationType" => try(lower(tostring(cv)), "unknown")
            if ck == "isolation_type"
          },
        )
      ]
    } if r.valid
  }

  rule_bodies = {
    for k, r in local.rules : k => merge(
      {
        for bk, bv in {
          id             = k
          displayName    = try(tostring(r.raw.display_name), k)
          description    = try(tostring(r.raw.description), null)
          status         = try(lower(tostring(r.raw.status)), "enabled")
          queryCondition = { queryText = try(tostring(r.raw.query), "") }
          schedule       = { frequency = try(upper(tostring(r.raw.frequency)), "PT24H") }
          detectionAction = merge(
            {
              alertTemplate = {
                for ak, av in {
                  title              = coalesce(try(tostring(r.raw.alert.title), null), try(tostring(r.raw.display_name), null), k)
                  description        = coalesce(try(tostring(r.raw.alert.description), null), try(tostring(r.raw.description), null), try(tostring(r.raw.display_name), null), k)
                  severity           = try(lower(tostring(r.raw.alert.severity)), "medium")
                  recommendedActions = try(tostring(r.raw.alert.recommended_actions), null)
                  customDetails      = can(keys(try(r.raw.alert.custom_details, 0))) ? r.raw.alert.custom_details : null
                  # The service currently rejects more than one tactic per rule (live 400: "Only
                  # one tactic is currently supported"), so only the FIRST authored tactic is sent;
                  # authoring keeps the full list (the docs model tactics as a collection) and the
                  # rules / mitre_coverage outputs report every authored tactic, ready to send them
                  # all the day the API accepts them.
                  tactics        = length(local.norm_mitre[k]) > 0 ? slice(local.norm_mitre[k], 0, 1) : null
                  entityMappings = length(local.norm_entity_mappings[k]) > 0 ? local.norm_entity_mappings[k] : null
                } : ak => av if av != null
              }
            },
            try(length(r.raw.device_groups) > 0, false) ? { organizationalScope = { deviceGroups = r.raw.device_groups } } : {},
            length(local.norm_automated_actions[k]) > 0 ? { automatedActions = local.norm_automated_actions[k] } : {},
          )
        } : bk => bv if bv != null
      },
      can(keys(try(r.raw.extra_body, 0))) ? r.raw.extra_body : {},
    ) if r.valid
  }
}
