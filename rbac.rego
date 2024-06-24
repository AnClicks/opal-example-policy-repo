# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets role mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., role mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package app.rbac

default allow = false
allow {
    input.role == "admin"
    input.action == "add"
}

allow {
    input.role == "admin"
    input.action == "delete"
}

allow {
    input.role == "admin"
    input.action == "edit"
}
allow {
    input.role == "viewer"
    input.action == "add"
    false
}

allow {
    input.role == "viewer"
    input.action == "delete"
    false
}

allow {
    input.role == "guest"
    input.action == "edit"
    false
}
