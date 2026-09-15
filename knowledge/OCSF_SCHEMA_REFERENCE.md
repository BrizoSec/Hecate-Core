# OCSF Schema Reference

Canonical OCSF field names for the event classes this program hunts in.

**This is a field dictionary, not a set of examples.** It exists so that
field names in generated research and rules are real OCSF paths rather
than plausible-looking inventions (`process_name`, `registry_key`,
`event_id` are none of them). Do not treat any name here as evidence that
a behaviour occurred, and do not select a field because it appears here —
select it because the behaviour under investigation would populate it.

Generated from the official OCSF schema at <https://schema.ocsf.io>.
Regenerate when the schema version changes; nothing reads it at runtime
except the researcher's telemetry-mapping step.

## Event classes

| Class | UID | Use for |
|-------|-----|---------|
| `process_activity` | 1007 | process creation, termination, injection |
| `network_activity` | 4001 | connections, flows, port/protocol |
| `dns_activity` | 4003 | name resolution, C2 over DNS |
| `file_activity` | 1001 | create/read/write/delete, drops |
| `module_activity` | 1005 | image and library loads |
| `authentication` | 3002 | logon, credential use |
| `registry_key_activity` | 201001 | key create/delete (Windows) |
| `registry_value_activity` | 201002 | value set/delete (Windows) |

## Objects and their fields

Field paths below are relative to the object. In an event, prefix with
the object's position — a process name is `process.name`, the acting
user is `actor.user.name`, the destination host is
`dst_endpoint.hostname`.

### `process` — Process

| Field | Type | Meaning |
|-------|------|---------|
| `name` | process_name_t | Name |
| `cmd_line` | string_t | Command Line |
| `pid` | integer_t | Process ID |
| `file` | object_t | File |
| `parent_process` | object_t | Parent Process |
| `user` | object_t | User |
| `created_time` | timestamp_t | Created Time |
| `integrity` | string_t | Integrity |

### `file` — File

| Field | Type | Meaning |
|-------|------|---------|
| `name` | file_name_t | Name |
| `path` | file_path_t | Path |
| `type` | string_t | Type |
| `hashes` | object_t | Hashes |
| `size` | long_t | Size |
| `created_time` | timestamp_t | Created Time |
| `signature` | object_t | Digital Signature |

### `actor` — Actor

| Field | Type | Meaning |
|-------|------|---------|
| `process` | object_t | Process |
| `user` | object_t | User |
| `session` | object_t | Session |
| `invoked_by` | string_t | Invoked by |

### `network_endpoint` — Network Endpoint

| Field | Type | Meaning |
|-------|------|---------|
| `ip` | ip_t | IP Address |
| `port` | port_t | Port |
| `hostname` | hostname_t | Hostname |
| `domain` | string_t | Domain |
| `mac` | mac_t | MAC Address |
| `svc_name` | string_t | Service Name |

### `device` — Device

| Field | Type | Meaning |
|-------|------|---------|
| `hostname` | hostname_t | Hostname |
| `ip` | ip_t | IP Address |
| `os` | object_t | OS |
| `type` | string_t | Type |
| `domain` | string_t | Domain |

### `user` — User

| Field | Type | Meaning |
|-------|------|---------|
| `name` | username_t | Name |
| `uid` | string_t | Unique ID |
| `domain` | string_t | Domain |
| `type` | string_t | Type |
| `email_addr` | email_t | Email Address |

### `dns_query` — DNS Query

| Field | Type | Meaning |
|-------|------|---------|
| `hostname` | hostname_t | Hostname |
| `type` | string_t | Resource Record Type |
| `class` | string_t | Resource Record Class |
| `opcode` | string_t | DNS Opcode |

### `module` — Module

| Field | Type | Meaning |
|-------|------|---------|
| `file` | object_t | File |
| `base_address` | string_t | Base Address |
| `load_type` | string_t | Load Type |
| `type` | string_t | Type |

### `reg_key` — Registry Key

| Field | Type | Meaning |
|-------|------|---------|
| `path` | reg_key_path_t | Path |
| `security_descriptor` | string_t | Security Descriptor |

### `reg_value` — Registry Value

| Field | Type | Meaning |
|-------|------|---------|
| `path` | reg_key_path_t | Path |
| `name` | string_t | Name |
| `data` | json_t | Data |
| `type` | string_t | Type |

## Common mistakes

| Not OCSF | Correct |
|----------|---------|
| `process_name` | `process.name` |
| `process.command_line` | `process.cmd_line` |
| `registry_key` | `reg_key.path` |
| `event_id` | class `uid` / `activity_id` |
| `file_path` | `file.path` |
| `user_account` | `actor.user.name` |
