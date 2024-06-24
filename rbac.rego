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

# Default deny all requests
default allow = false

# Allow admins to edit, delete, and add
allow {
    user_is_admin
    input.action == "edit"   # Admin can edit
}

allow {
    user_is_admin
    input.action == "delete" # Admin can delete
}

allow {
    user_is_admin
    input.action == "add"    # Admin can add
}

# Function to check if the user is an admin
user_is_admin {
    some i
    data.users[input.user].roles[i] == "admin"
}

# Viewers cannot perform any actions
allow {
    user_is_viewer
    false # Explicitly deny viewers from performing any action
}

# Function to check if the user is a viewer
user_is_viewer {
    some i
    data.users[input.user].roles[i] == "viewer"
}
