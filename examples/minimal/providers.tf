# The msgraph provider authenticates from the environment (Azure CLI locally, or the ARM_* / OIDC
# variables in CI), the same way the azuread provider does. No explicit configuration is needed.
provider "msgraph" {}
