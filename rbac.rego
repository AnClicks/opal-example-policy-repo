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

# Define roles and their permissions
role_permissions = {
    "admin": {
        "canAdd": true,
        "canEdit": true,
        "canDelete": true
    },
    "viewer": {
        "canAdd": false,
        "canEdit": false,
        "canDelete": false
    }
}

# Input is expected to contain role and action
# Example input: {"input": {"role": "admin", "action": "canAdd"}}
allow {
    input.role == "admin"
    action_allowed[input.role][input.action]
}

allow {
    input.role == "viewer"
    action_allowed[input.role][input.action]
}

# Helper rule to map roles to their permissions
action_allowed[role][action] {
    role_permissions[role][action]
}