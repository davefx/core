"""Permission constants."""

CAT_ENTITIES = "entities"
CAT_CONFIG_ENTRIES = "config_entries"
CAT_SERVICES = "services"
CAT_AUTOMATIONS = "automations"
CAT_ADMIN = "admin"
SUBCAT_ALL = "all"

POLICY_READ = "read"
POLICY_CONTROL = "control"
POLICY_EDIT = "edit"
POLICY_TRIGGER = "trigger"
POLICY_MANAGE = "manage"

ENTITY_LABEL_IDS = "label_ids"
GROUP_IDS = "group_ids"

# Management capabilities (delegated administration). Modelled on Keycloak's
# fine-grained group permissions; the escalation guard is the Kubernetes RBAC
# "you can only grant what you already hold" rule.
ADMIN_MANAGE_GROUPS = "manage_groups"  # global: create/delete custom groups
ADMIN_MANAGE_AUTOMATIONS = "manage_automations"  # global: author automations
ADMIN_MANAGE_SCRIPTS = "manage_scripts"  # global: author scripts
ADMIN_MANAGE_SCENES = "manage_scenes"  # global: author scenes
ADMIN_ESCALATE = "escalate"  # grant permissions you don't hold yourself
ADMIN_GROUPS = "groups"  # per-group scopes below
SCOPE_VIEW = "view"
SCOPE_MANAGE = "manage"  # edit a group's policy / ACL rules
SCOPE_MANAGE_MEMBERS = "manage_members"  # add/remove users to/from a group
