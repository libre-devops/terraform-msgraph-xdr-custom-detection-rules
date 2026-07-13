<!--
  Header for the complete example README. Edit this file, then run `just docs`
  (or ./Sort-LdoTerraform.ps1 -IncludeExamples) to regenerate the section between the markers.
  The example's main.tf is embedded into the README automatically (see .terraform-docs.yml).
-->
<div align="center">
  <a href="https://libredevops.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
      <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="200">
    </picture>
  </a>
</div>

# Complete example

Every feature at once: the curated baseline with per rule overrides (a rule parked in disabled
tuning mode, another retuned to a quieter schedule and severity), analyst authored YAML rules from
`custom-detections/` including a doubly inert demonstration of the gated automated response
actions, an HCL authored rule through `custom_rules`, and an `id_prefix` namespacing everything the
call owns. Live applies stay alert free: the action carrying rule is disabled and unmatchable.
Needs `CustomDetection.ReadWrite.All` on a Defender XDR tenant.
