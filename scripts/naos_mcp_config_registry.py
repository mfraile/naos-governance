#!/usr/bin/env python3
"""Canonical, metadata-only MCP config discovery for NAOS.

This module deliberately does not install clients, call MCP servers, inspect
memory payloads, or treat configuration presence as usable tool access.
"""

from __future__ import annotations

import hashlib
import json
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


SECRET_KEY_MARKERS = (
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "connection_string",
    "connectionstring",
    "private_key",
)
ENGRAM_TOOL_NAMES = {
    "get_observation",
    "mem_context",
    "mem_current_project",
    "mem_get_observation",
    "mem_save",
    "mem_search",
    "mem_session_summary",
}
MAX_CONFIG_BYTES = 1_000_000
DESCRIPTOR_REVIEW_SCHEMA = "naos.mcp_descriptor_review_policy.v1"
DESCRIPTOR_REVIEW_VERSION = "1.0.0"
DESCRIPTOR_POLICY_SHA256 = "2a5b39d7f89673df223f35890393da528ae413b4979e3766be155aea37c30375"
DESCRIPTOR_REVIEW_DISPOSITIONS = {
    "allowlisted_pending_activation",
    "review_required",
}
EXECUTION_OR_AUTH_FIELDS = {
    "apiKey",
    "api_key",
    "args",
    "auth",
    "authorization",
    "command",
    "env",
    "environment",
    "headers",
    "oauth",
    "token",
}
REPORTABLE_SERVER_FIELDS = EXECUTION_OR_AUTH_FIELDS | {
    "enabled",
    "endpoint",
    "toolNames",
    "tool_names",
    "tools",
    "transport",
    "type",
    "url",
}


@dataclass(frozen=True, slots=True)
class MCPConfigDescriptor:
    """Immutable description of one supported MCP-related config location."""

    id: str
    path: str
    scope: str
    kind: str
    clients: tuple[str, ...]
    config_format: str = "json"
    server_keys: tuple[str, ...] = ("servers", "mcpServers")
    project_keys: tuple[str, ...] = ()


WORKSPACE_SERVER_CONFIGS: tuple[MCPConfigDescriptor, ...] = (
    MCPConfigDescriptor(
        id="vscode_workspace_mcp",
        path=".vscode/mcp.json",
        scope="workspace",
        kind="server_definition",
        clients=("vs_code", "local_ide_agents"),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="cursor_workspace_mcp",
        path=".cursor/mcp.json",
        scope="workspace",
        kind="server_definition",
        clients=("cursor", "local_ide_agents"),
        server_keys=("mcpServers", "servers"),
    ),
    MCPConfigDescriptor(
        id="workspace_mcp",
        path=".mcp.json",
        scope="workspace",
        kind="server_definition",
        clients=("claude_code", "gemini_cli", "local_ide_agents"),
        server_keys=("mcpServers", "servers"),
    ),
    MCPConfigDescriptor(
        id="ai_workspace_mcp",
        path=".ai/mcp.json",
        scope="workspace",
        kind="server_definition",
        clients=("claude_code", "gemini_cli", "local_ide_agents"),
        server_keys=("servers", "mcpServers"),
    ),
    MCPConfigDescriptor(
        id="root_workspace_mcp",
        path="mcp.json",
        scope="workspace",
        kind="server_definition",
        clients=("local_ide_agents",),
        server_keys=("servers", "mcpServers"),
    ),
    MCPConfigDescriptor(
        id="antigravity_workspace_mcp",
        path=".agents/mcp_config.json",
        scope="workspace",
        kind="server_definition",
        clients=("antigravity", "local_ide_agents"),
        server_keys=("mcpServers",),
    ),
    MCPConfigDescriptor(
        id="kilo_workspace_mcp",
        path=".kilo/kilo.jsonc",
        scope="workspace",
        kind="server_definition",
        clients=("kilo", "local_ide_agents"),
        config_format="jsonc",
        server_keys=("mcp",),
    ),
    MCPConfigDescriptor(
        id="opencode_workspace_mcp",
        path="opencode.json",
        scope="workspace",
        kind="server_definition",
        clients=("opencode", "local_ide_agents"),
        server_keys=("mcp",),
    ),
)

WORKSPACE_PROJECT_CONFIGS: tuple[MCPConfigDescriptor, ...] = (
    MCPConfigDescriptor(
        id="engram_workspace_project",
        path=".engram/config.json",
        scope="workspace",
        kind="project_identity",
        clients=("engram_project_adapter",),
        server_keys=(),
        project_keys=("project_name",),
    ),
)

WORKSPACE_CLIENT_POLICY_CONFIGS: tuple[MCPConfigDescriptor, ...] = (
    MCPConfigDescriptor(
        id="claude_workspace_policy",
        path=".claude/settings.json",
        scope="workspace",
        kind="client_policy",
        clients=("claude_code",),
    ),
)

USER_SERVER_CONFIGS: tuple[MCPConfigDescriptor, ...] = (
    MCPConfigDescriptor(
        id="codex_user_mcp",
        path="~/.codex/config.toml",
        scope="user",
        kind="server_definition",
        clients=("codex",),
        config_format="toml",
        server_keys=("mcp_servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_user_mcp_macos",
        path="~/Library/Application Support/Code/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_insiders_user_mcp_macos",
        path="~/Library/Application Support/Code - Insiders/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_user_mcp_xdg",
        path="~/.config/Code/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_insiders_user_mcp_xdg",
        path="~/.config/Code - Insiders/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_user_mcp_windows",
        path="~/AppData/Roaming/Code/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="vscode_insiders_user_mcp_windows",
        path="~/AppData/Roaming/Code - Insiders/User/mcp.json",
        scope="user",
        kind="server_definition",
        clients=("vs_code",),
        server_keys=("servers",),
    ),
    MCPConfigDescriptor(
        id="copilot_agent_host_user_mcp",
        path="~/.copilot/mcp-config.json",
        scope="user",
        kind="server_definition",
        clients=("copilot_agent_host",),
        server_keys=("mcpServers", "servers"),
    ),
    MCPConfigDescriptor(
        id="claude_user_mcp",
        path="~/.claude.json",
        scope="user",
        kind="server_definition",
        clients=("claude_code",),
        server_keys=("mcpServers",),
    ),
    MCPConfigDescriptor(
        id="antigravity_user_mcp",
        path="~/.gemini/config/mcp_config.json",
        scope="user",
        kind="server_definition",
        clients=("antigravity",),
        server_keys=("mcpServers",),
    ),
    MCPConfigDescriptor(
        id="antigravity_cli_user_mcp",
        path="~/.gemini/antigravity-cli/mcp_config.json",
        scope="user",
        kind="server_definition",
        clients=("antigravity",),
        server_keys=("mcpServers",),
    ),
    MCPConfigDescriptor(
        id="kilo_user_mcp",
        path="~/.config/kilo/kilo.jsonc",
        scope="user",
        kind="server_definition",
        clients=("kilo",),
        config_format="jsonc",
        server_keys=("mcp",),
    ),
    MCPConfigDescriptor(
        id="opencode_user_mcp",
        path="~/.config/opencode/opencode.json",
        scope="user",
        kind="server_definition",
        clients=("opencode",),
        server_keys=("mcp",),
    ),
    MCPConfigDescriptor(
        id="opencode_user_mcp_jsonc",
        path="~/.config/opencode/opencode.jsonc",
        scope="user",
        kind="server_definition",
        clients=("opencode",),
        config_format="jsonc",
        server_keys=("mcp",),
    ),
    MCPConfigDescriptor(
        id="muse_user_mcp",
        path="~/.config/muse/settings.json",
        scope="user",
        kind="server_definition",
        clients=("muse",),
        server_keys=("mcp_servers",),
    ),
)

USER_CLIENT_POLICY_CONFIGS: tuple[MCPConfigDescriptor, ...] = (
    MCPConfigDescriptor(
        id="claude_user_policy",
        path="~/.claude/settings.json",
        scope="user",
        kind="client_policy",
        clients=("claude_code",),
        server_keys=(),
    ),
)


def config_descriptors(
    *,
    include_user: bool = False,
    include_client_policy: bool = False,
) -> tuple[MCPConfigDescriptor, ...]:
    """Return the selected immutable registry entries in deterministic order."""

    selected = list(WORKSPACE_SERVER_CONFIGS)
    selected.extend(WORKSPACE_PROJECT_CONFIGS)
    if include_client_policy:
        selected.extend(WORKSPACE_CLIENT_POLICY_CONFIGS)
    if include_user:
        selected.extend(USER_SERVER_CONFIGS)
    if include_user and include_client_policy:
        selected.extend(USER_CLIENT_POLICY_CONFIGS)
    return tuple(selected)


def _descriptor_path(descriptor: MCPConfigDescriptor, root: Path, home: Path) -> Path:
    if descriptor.scope == "workspace":
        return root / descriptor.path
    prefix = "~/"
    if descriptor.path.startswith(prefix):
        return home / descriptor.path[len(prefix) :]
    return Path(descriptor.path).expanduser()


def _string_value(value: Any) -> str | None:
    """Return a declared string without serializing arbitrary JSON values."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [text] if (text := value.strip()) else []
    if isinstance(value, (list, tuple)):
        return [text for item in value if isinstance(item, str) and (text := item.strip())]
    return []


def _server_tools(server: Mapping[str, Any]) -> list[str]:
    tools: list[str] = []
    for key in ("tools", "toolNames", "tool_names"):
        tools.extend(_as_strings(server.get(key)))
    return list(dict.fromkeys(tools))


def _canonical_sha256(value: Any) -> str:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _nonnegative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else -1


def _safe_remote_endpoint(server: Mapping[str, Any]) -> dict[str, Any]:
    """Return only non-reversible review metadata for a declared remote endpoint."""

    endpoint_keys = [key for key in ("url", "endpoint") if key in server]
    result: dict[str, Any] = {
        "endpoint_declared": bool(endpoint_keys),
        "endpoint_key": endpoint_keys[0] if len(endpoint_keys) == 1 else None,
        "endpoint_safe_for_static_review": False,
        "endpoint_sha256": None,
        "endpoint_shape_status": "missing",
    }
    if not endpoint_keys:
        return result
    if len(endpoint_keys) != 1:
        result["endpoint_shape_status"] = "multiple_endpoint_fields"
        return result
    raw_endpoint = server.get(endpoint_keys[0])
    if not isinstance(raw_endpoint, str) or not raw_endpoint.strip():
        result["endpoint_shape_status"] = "non_string"
        return result
    if raw_endpoint != raw_endpoint.strip():
        result["endpoint_shape_status"] = "unsafe_whitespace"
        return result
    try:
        parsed = urlsplit(raw_endpoint)
    except ValueError:
        result["endpoint_shape_status"] = "invalid"
        return result
    if parsed.scheme.casefold() != "https":
        result["endpoint_shape_status"] = "unsafe_scheme"
        return result
    if parsed.username is not None or parsed.password is not None:
        result["endpoint_shape_status"] = "unsafe_userinfo"
        return result
    if parsed.query:
        result["endpoint_shape_status"] = "unsafe_query"
        return result
    if parsed.fragment:
        result["endpoint_shape_status"] = "unsafe_fragment"
        return result
    try:
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        result["endpoint_shape_status"] = "invalid"
        return result
    if not hostname or parsed.scheme.casefold() != "https":
        result["endpoint_shape_status"] = "invalid"
        return result
    result.update(
        {
            "endpoint_safe_for_static_review": True,
            "endpoint_sha256": hashlib.sha256(raw_endpoint.encode("utf-8")).hexdigest(),
            "endpoint_shape_status": "safe_https",
        }
    )
    return result


def _is_engram_server(name: str, server: Mapping[str, Any]) -> bool:
    identity_parts = [name]
    identity_parts.extend(_as_strings(server.get("command")))
    identity_parts.extend(_as_strings(server.get("args")))
    if any("engram" in part.lower() for part in identity_parts):
        return True
    return bool({tool.lower() for tool in _server_tools(server)} & ENGRAM_TOOL_NAMES)


def _secret_like_keys(keys: Iterable[Any]) -> list[str]:
    result = []
    for raw_key in keys:
        key = str(raw_key)
        lowered = key.lower()
        if any(marker in lowered for marker in SECRET_KEY_MARKERS):
            result.append(key)
    return sorted(set(result))


def _empty_row(descriptor: MCPConfigDescriptor) -> dict[str, Any]:
    if descriptor.scope == "workspace":
        path_base = "workspace"
    elif descriptor.path.startswith("~/"):
        path_base = "user_home"
    else:
        path_base = "absolute" if Path(descriptor.path).is_absolute() else "caller_relative"
    return {
        "config_id": descriptor.id,
        "path": descriptor.path,
        "path_base": path_base,
        "path_is_absolute": Path(descriptor.path).is_absolute(),
        "scope": descriptor.scope,
        "kind": descriptor.kind,
        "config_format": descriptor.config_format,
        "clients": list(descriptor.clients),
        "exists": False,
        "status": "missing",
        "size_bytes": None,
        "modified_at_ns": None,
        "servers": [],
        "engram_servers": [],
        "engram_projects": [],
        "engram_project_declarations": [],
        "server_declarations": [],
        "tools_declared": [],
        "mentions_memory": False,
        "mentions_engram": False,
        "secret_like_keys": [],
        "has_secret_like_key": False,
        "metadata_only": True,
        "secret_values_reported": False,
        "payload_read": False,
        "access_verified": False,
    }


def _strip_jsonc(text: str) -> str:
    """Remove JSONC comments and trailing commas without altering strings."""

    stripped: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            stripped.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            stripped.append(char)
            index += 1
            continue
        if char == "/" and following == "/":
            stripped.extend((" ", " "))
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                stripped.append(" ")
                index += 1
            continue
        if char == "/" and following == "*":
            stripped.extend((" ", " "))
            index += 2
            while index < len(text):
                if index + 1 < len(text) and text[index] == "*" and text[index + 1] == "/":
                    stripped.extend((" ", " "))
                    index += 2
                    break
                stripped.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        stripped.append(char)
        index += 1

    without_comments = "".join(stripped)
    result: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(without_comments):
        char = without_comments[index]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(without_comments) and without_comments[lookahead].isspace():
                lookahead += 1
            if lookahead < len(without_comments) and without_comments[lookahead] in "}]":
                index += 1
                continue
        result.append(char)
        index += 1
    return "".join(result)


def _json_mapping(text: str, *, jsonc: bool) -> Mapping[str, Any] | None:
    try:
        parsed = json.loads(_strip_jsonc(text) if jsonc else text)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _environment_mappings(server: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        value
        for key in ("env", "environment")
        if isinstance((value := server.get(key)), Mapping)
    ]


def _append_server_metadata(
    row: dict[str, Any],
    descriptor: MCPConfigDescriptor,
    *,
    container: str,
    name: str,
    server: Mapping[str, Any],
) -> None:
    secret_keys: list[str] = []
    projects: list[str] = []
    env_keys: list[str] = []
    is_engram = _is_engram_server(name, server)
    for environment in _environment_mappings(server):
        mapping_keys = [str(key) for key in environment]
        env_keys.extend(mapping_keys)
        secret_keys.extend(_secret_like_keys(mapping_keys))
        if is_engram and (project := _string_value(environment.get("ENGRAM_PROJECT"))):
            projects.append(project)

    unique_projects = sorted(set(projects))
    server_secret_keys = sorted(set(secret_keys))
    all_declared_keys = sorted(str(key) for key in server)
    declared_keys = [key for key in all_declared_keys if key in REPORTABLE_SERVER_FIELDS]
    endpoint_metadata = _safe_remote_endpoint(server)
    transport_field = "type" if "type" in server else ("transport" if "transport" in server else None)
    raw_transport = server.get(transport_field) if transport_field else None
    transport = raw_transport if isinstance(raw_transport, str) else None
    row["server_declarations"].append(
        {
            "config_id": descriptor.id,
            "config_path": row["path"],
            "scope": descriptor.scope,
            "clients": list(descriptor.clients),
            "container": container,
            "name": name,
            "type": _string_value(server.get("type")),
            "declared_keys": declared_keys,
            "declared_key_count": len(all_declared_keys),
            "declared_keys_sha256": _canonical_sha256(all_declared_keys),
            "unreported_declared_key_count": len(all_declared_keys) - len(declared_keys),
            "transport_field": transport_field,
            "transport": transport,
            "command_declared": bool(server.get("command")),
            "execution_or_auth_fields_declared": sorted(
                key for key in declared_keys if key in EXECUTION_OR_AUTH_FIELDS
            ),
            "env_keys": sorted(set(env_keys)),
            "secret_like_keys": server_secret_keys,
            "is_engram": is_engram,
            "has_engram_project": bool(unique_projects),
            "project": unique_projects[0] if len(unique_projects) == 1 else None,
            "projects": unique_projects,
            "access_verified": False,
            **endpoint_metadata,
        }
    )
    for tool in _server_tools(server):
        row["tools_declared"].append(
            {
                "config_path": row["path"],
                "server": name,
                "tool": tool,
                "access_verified": False,
            }
        )
    if not is_engram:
        row["secret_like_keys"].extend(server_secret_keys)
        return

    row["engram_servers"].append(name)
    row["engram_projects"].extend(unique_projects)
    for project in unique_projects:
        row["engram_project_declarations"].append(
            {
                "config_path": row["path"],
                "scope": descriptor.scope,
                "clients": list(descriptor.clients),
                "server": name,
                "project": project,
                "source_kind": "server_environment",
            }
        )
    row["secret_like_keys"].extend(server_secret_keys)


def _scan_json_servers(
    row: dict[str, Any],
    descriptor: MCPConfigDescriptor,
    parsed: Mapping[str, Any],
) -> None:
    seen_servers: set[tuple[str, str]] = set()
    for container in descriptor.server_keys:
        servers = parsed.get(container)
        if not isinstance(servers, Mapping):
            continue
        for raw_name, raw_server in sorted(servers.items(), key=lambda item: str(item[0])):
            name = str(raw_name)
            identity = (container, name)
            if identity in seen_servers:
                continue
            seen_servers.add(identity)
            row["servers"].append(name)
            server = raw_server if isinstance(raw_server, Mapping) else {}
            _append_server_metadata(
                row,
                descriptor,
                container=container,
                name=name,
                server=server,
            )


def _scan_toml_servers(row: dict[str, Any], descriptor: MCPConfigDescriptor, text: str) -> bool:
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    servers = parsed.get("mcp_servers")
    if not isinstance(servers, Mapping):
        return True
    for raw_name, raw_server in sorted(servers.items(), key=lambda item: str(item[0])):
        name = str(raw_name)
        row["servers"].append(name)
        _append_server_metadata(
            row,
            descriptor,
            container="mcp_servers",
            name=name,
            server=raw_server if isinstance(raw_server, Mapping) else {},
        )
    return True


def _scan_project_identity(
    row: dict[str, Any],
    descriptor: MCPConfigDescriptor,
    parsed: Mapping[str, Any],
) -> None:
    for key in descriptor.project_keys:
        project = _string_value(parsed.get(key))
        if not project:
            continue
        row["engram_projects"].append(project)
        row["engram_project_declarations"].append(
            {
                "config_path": row["path"],
                "scope": descriptor.scope,
                "clients": list(descriptor.clients),
                "server": None,
                "project": project,
                "source_kind": "project_identity",
            }
        )


def _finalize_row(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("servers", "engram_servers", "engram_projects", "secret_like_keys"):
        row[key] = sorted(set(row[key]))
    row["has_secret_like_key"] = bool(row["secret_like_keys"])
    row["mentions_engram"] = bool(row["engram_servers"])
    declared_tools = {str(item.get("tool") or "").casefold() for item in row["tools_declared"]}
    row["mentions_memory"] = bool(row["engram_servers"] or declared_tools & ENGRAM_TOOL_NAMES)
    return row


def _workspace_parent_refusal(
    descriptor: MCPConfigDescriptor,
    path: Path,
    workspace_root: Path,
) -> str | None:
    if descriptor.scope != "workspace":
        return None
    try:
        relative = path.relative_to(workspace_root)
    except ValueError:
        return "workspace_boundary_refused"
    if ".." in relative.parts:
        return "workspace_boundary_refused"

    current = workspace_root
    for component in relative.parts[:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError:
            return "workspace_boundary_refused"
        if stat.S_ISLNK(metadata.st_mode):
            return "symlink_refused"
    return None


def _scan_descriptor(
    descriptor: MCPConfigDescriptor,
    path: Path,
    workspace_root: Path,
) -> dict[str, Any]:
    row = _empty_row(descriptor)
    if refusal := _workspace_parent_refusal(descriptor, path, workspace_root):
        row["status"] = refusal
        return row
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return row
    except OSError:
        row["status"] = "metadata_error"
        return row
    if path.is_symlink():
        row["exists"] = True
        row["status"] = "symlink_refused"
        row["size_bytes"] = metadata.st_size
        row["modified_at_ns"] = metadata.st_mtime_ns
        return row
    if not path.is_file():
        return row
    if descriptor.scope == "workspace":
        try:
            path.resolve(strict=True).relative_to(workspace_root)
        except (OSError, RuntimeError, ValueError):
            row["status"] = "workspace_boundary_refused"
            return row

    row["exists"] = True
    row["status"] = "present"
    row["size_bytes"] = metadata.st_size
    row["modified_at_ns"] = metadata.st_mtime_ns
    if metadata.st_size > MAX_CONFIG_BYTES:
        row["status"] = "size_limit_exceeded"
        return row
    if descriptor.kind == "client_policy":
        return row

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        row["status"] = "read_error"
        return row

    if descriptor.config_format == "toml":
        if descriptor.kind != "server_definition":
            return row
        if not _scan_toml_servers(row, descriptor, text):
            row["status"] = "parse_error"
        return _finalize_row(row)

    parsed = _json_mapping(text, jsonc=descriptor.config_format == "jsonc")
    if parsed is None:
        row["status"] = "parse_error"
        return row
    if descriptor.kind == "project_identity":
        _scan_project_identity(row, descriptor, parsed)
        return _finalize_row(row)
    if descriptor.kind == "server_definition":
        _scan_json_servers(row, descriptor, parsed)
    return _finalize_row(row)


def scan_mcp_configs(
    root: Path,
    *,
    include_user: bool = False,
    include_client_policy: bool = False,
    home: Path | None = None,
    descriptors: Sequence[MCPConfigDescriptor] | None = None,
) -> list[dict[str, Any]]:
    """Inspect selected config files as bounded, declaration-only metadata."""

    project_root = root.resolve()
    user_home = (home or Path.home()).resolve()
    selected = tuple(descriptors) if descriptors is not None else config_descriptors(
        include_user=include_user,
        include_client_policy=include_client_policy,
    )
    return [
        _scan_descriptor(
            descriptor,
            _descriptor_path(descriptor, project_root, user_home),
            project_root,
        )
        for descriptor in selected
    ]


def _review_declarations(configs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for config in configs:
        if not config.get("exists", True) or str(config.get("kind") or "server_definition") != "server_definition":
            continue
        for raw in config.get("server_declarations", []):
            if not isinstance(raw, Mapping):
                continue
            declaration = dict(raw)
            declaration.setdefault("config_id", str(config.get("config_id") or ""))
            declaration.setdefault("config_path", str(config.get("path") or "unknown"))
            declarations.append(declaration)
    return declarations


def _policy_rule_is_valid(rule: Mapping[str, Any]) -> bool:
    if _string_value(rule.get("rule_id")) is None:
        return False
    basis = rule.get("basis")
    if not isinstance(basis, Mapping):
        return False
    approved_basis_sha256 = _string_value(rule.get("approved_basis_sha256"))
    if not approved_basis_sha256 or approved_basis_sha256 != _canonical_sha256(basis):
        return False
    if _string_value(rule.get("disposition")) not in DESCRIPTOR_REVIEW_DISPOSITIONS:
        return False
    if _string_value(rule.get("disposition")) != "allowlisted_pending_activation":
        return False
    if _string_value(basis.get("descriptor_id")) is None:
        return False
    for key in ("config_ids", "containers", "declared_keys"):
        values = basis.get(key)
        if not isinstance(values, list) or not values or not all(_string_value(item) for item in values):
            return False
    if _string_value(basis.get("transport_field")) not in {"type", "transport"}:
        return False
    if _string_value(basis.get("transport")) is None:
        return False
    if _string_value(basis.get("endpoint_key")) not in {"url", "endpoint"}:
        return False
    endpoint = _string_value(basis.get("endpoint"))
    endpoint_sha256 = _string_value(basis.get("endpoint_sha256"))
    if not endpoint or not endpoint_sha256:
        return False
    endpoint_metadata = _safe_remote_endpoint({str(basis["endpoint_key"]): endpoint})
    if (
        endpoint_metadata.get("endpoint_shape_status") != "safe_https"
        or endpoint_metadata.get("endpoint_sha256") != endpoint_sha256
    ):
        return False
    risk_owner = basis.get("risk_owner")
    if not isinstance(risk_owner, Mapping):
        return False
    if _string_value(risk_owner.get("role")) is None or _string_value(risk_owner.get("authority_ref")) is None:
        return False
    return _string_value(basis.get("pinning")) == "exact_static_declaration_tuple"


def _rule_mismatch_codes(declaration: Mapping[str, Any], basis: Mapping[str, Any]) -> list[str]:
    codes: list[str] = []
    if str(declaration.get("config_id") or "") not in {str(item) for item in basis.get("config_ids", [])}:
        codes.append("config_id_mismatch")
    if str(declaration.get("container") or "") not in {str(item) for item in basis.get("containers", [])}:
        codes.append("container_mismatch")
    if sorted(str(item) for item in declaration.get("declared_keys", [])) != sorted(
        str(item) for item in basis.get("declared_keys", [])
    ) or _nonnegative_int(declaration.get("declared_key_count")) != len(basis.get("declared_keys", [])):
        codes.append("declared_field_set_mismatch")
    if str(declaration.get("transport_field") or "") != str(basis.get("transport_field") or ""):
        codes.append("transport_field_mismatch")
    if declaration.get("transport") != basis.get("transport"):
        codes.append("transport_mismatch")
    if str(declaration.get("endpoint_key") or "") != str(basis.get("endpoint_key") or ""):
        codes.append("endpoint_key_mismatch")
    if declaration.get("endpoint_shape_status") != "safe_https":
        codes.append("endpoint_not_safe_https")
    if str(declaration.get("endpoint_sha256") or "") != str(basis.get("endpoint_sha256") or ""):
        codes.append("endpoint_pin_mismatch")
    if declaration.get("execution_or_auth_fields_declared"):
        codes.append("execution_or_auth_fields_declared")
    return sorted(set(codes))


def review_mcp_descriptors(
    configs: Sequence[Mapping[str, Any]],
    rules_payload: Mapping[str, Any] | None,
    *,
    rules_path: str = "naos/memory_mcp_inventory_rules.yaml",
) -> dict[str, Any]:
    """Review static MCP declarations without activation, authentication, or calls."""

    declarations = _review_declarations(configs)
    load_error = (
        _string_value(rules_payload.get("_descriptor_review_load_error"))
        if isinstance(rules_payload, Mapping)
        else None
    )
    section = rules_payload.get("descriptor_review") if isinstance(rules_payload, Mapping) else None
    policy_status = "not_configured"
    integrity_status = "missing"
    policy_sha256: str | None = None
    rules: list[Mapping[str, Any]] = []
    policy_reason = "descriptor_review_not_configured"

    if load_error:
        policy_status = "invalid_rules"
        integrity_status = "invalid"
        policy_reason = load_error
    elif section is not None:
        policy_status = "invalid_rules"
        integrity_status = "invalid"
        policy_reason = "descriptor_review_policy_invalid"
        if isinstance(section, Mapping):
            projection = dict(section)
            declared_policy_sha256 = _string_value(projection.pop("policy_integrity_sha256", None))
            policy_sha256 = _canonical_sha256(projection)
            raw_rules = section.get("rules")
            if declared_policy_sha256 and (
                declared_policy_sha256 != policy_sha256
                or policy_sha256 != DESCRIPTOR_POLICY_SHA256
            ):
                integrity_status = "drifted"
                policy_reason = "descriptor_review_policy_drifted"
            elif (
                section.get("schema") == DESCRIPTOR_REVIEW_SCHEMA
                and str(section.get("version") or "") == DESCRIPTOR_REVIEW_VERSION
                and section.get("default_disposition") == "review_required"
                and declared_policy_sha256 == policy_sha256 == DESCRIPTOR_POLICY_SHA256
                and isinstance(raw_rules, list)
                and raw_rules
                and all(isinstance(item, Mapping) and _policy_rule_is_valid(item) for item in raw_rules)
            ):
                policy_status = "valid"
                integrity_status = "valid"
                policy_reason = "descriptor_review_policy_valid"
                rules = [item for item in raw_rules if isinstance(item, Mapping)]

    reviews: list[dict[str, Any]] = []
    for declaration in declarations:
        observed_tuple = {
            "config_id": str(declaration.get("config_id") or ""),
            "container": str(declaration.get("container") or ""),
            "declared_keys": sorted(str(item) for item in declaration.get("declared_keys", [])),
            "declared_key_count": _nonnegative_int(declaration.get("declared_key_count")),
            "declared_keys_sha256": declaration.get("declared_keys_sha256"),
            "transport_field": declaration.get("transport_field"),
            "transport": declaration.get("transport"),
            "endpoint_key": declaration.get("endpoint_key"),
            "endpoint_sha256": declaration.get("endpoint_sha256"),
        }
        declaration_ref = _canonical_sha256(
            {
                "config_id": declaration.get("config_id"),
                "config_path": declaration.get("config_path"),
                "container": declaration.get("container"),
                "server_label": declaration.get("name"),
            }
        )
        matched_rule: Mapping[str, Any] | None = None
        mismatch_codes: list[str] = []
        if policy_status == "valid":
            for rule in rules:
                basis = rule.get("basis")
                if not isinstance(basis, Mapping):
                    continue
                candidate_codes = _rule_mismatch_codes(declaration, basis)
                if not candidate_codes:
                    matched_rule = rule
                    break
                mismatch_codes.extend(candidate_codes)

        allowed = matched_rule is not None
        if policy_status != "valid":
            reason_codes = [policy_reason]
        elif allowed:
            reason_codes = ["exact_static_declaration_tuple_matched"]
        else:
            reason_codes = sorted(set(mismatch_codes or ["no_matching_allowlist_rule"]))
        matched_basis = matched_rule.get("basis") if isinstance(matched_rule, Mapping) else None
        risk_owner = matched_basis.get("risk_owner") if isinstance(matched_basis, Mapping) else None
        reviews.append(
            {
                "declaration_ref": declaration_ref,
                "config_id": str(declaration.get("config_id") or ""),
                "observed_tuple_sha256": _canonical_sha256(observed_tuple),
                "policy_rule_id": _string_value(matched_rule.get("rule_id")) if isinstance(matched_rule, Mapping) else None,
                "status": "allowlisted_pending_activation" if allowed else "review_required",
                "reason_codes": reason_codes,
                "risk_owner_authority_declared": bool(
                    isinstance(risk_owner, Mapping)
                    and _string_value(risk_owner.get("role"))
                    and _string_value(risk_owner.get("authority_ref"))
                ),
                "risk_owner_identity_verified": False,
                "pin_declared": bool(
                    isinstance(matched_basis, Mapping)
                    and _string_value(matched_basis.get("endpoint_sha256"))
                    and isinstance(matched_rule, Mapping)
                    and _string_value(matched_rule.get("approved_basis_sha256"))
                ),
                "pin_verified": False,
                "static_declaration_pin_matched": allowed,
                "server_label_used_as_identity": False,
                "human_review_required": True,
            }
        )

    counts = {
        disposition: sum(1 for item in reviews if item["status"] == disposition)
        for disposition in sorted(DESCRIPTOR_REVIEW_DISPOSITIONS)
    }
    if policy_status == "valid" and counts["review_required"]:
        report_status = "review_required"
    else:
        report_status = policy_status
    return {
        "status": report_status,
        "rules_path": rules_path,
        "rules_sha256": policy_sha256,
        "expected_rules_sha256": DESCRIPTOR_POLICY_SHA256,
        "policy_integrity_status": integrity_status,
        "policy_schema": DESCRIPTOR_REVIEW_SCHEMA,
        "policy_version": DESCRIPTOR_REVIEW_VERSION,
        "policy_rule_count": len(rules),
        "declaration_count": len(declarations),
        "summary": counts,
        "activation_performed": False,
        "authentication_verified": False,
        "live_access_verified": False,
        "tool_authority_verified": False,
        "write_authority_verified": False,
        "provider_calls_performed": False,
        "remote_identity_verified": False,
        "declaration_reviews": reviews,
        "non_claims": [
            "policy allowlisting is not MCP activation or authentication",
            "static endpoint matching does not verify remote server identity or behavior",
            "tool availability, safety, and write authority are not verified",
            "remote implementation and tool-list drift are not observable offline",
        ],
    }


def summarize_mcp_configs(configs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the common declaration-only summary consumed by NAOS reports."""

    rows = [dict(item) for item in configs]
    present = [item for item in rows if item.get("exists")]
    engram = [item for item in present if item.get("engram_servers")]
    declarations = [
        dict(declaration)
        for item in present
        for declaration in item.get("engram_project_declarations", [])
        if isinstance(declaration, dict)
    ]
    servers_declared = [
        dict(server)
        for item in present
        for server in item.get("server_declarations", [])
        if isinstance(server, dict)
    ]
    tools_declared = [
        dict(tool)
        for item in present
        for tool in item.get("tools_declared", [])
        if isinstance(tool, dict)
    ]
    observed_clients = sorted(
        {
            str(client)
            for item in engram
            for client in item.get("clients", [])
            if str(client).strip()
        }
    )
    return {
        "status": "present" if present else "not_configured",
        "project_config_files": rows,
        "present_config_files": len(present),
        "present_server_config_files": sum(1 for item in present if item.get("kind") == "server_definition"),
        "engram_config_paths": [str(item.get("path")) for item in engram],
        "project_identity_config_paths": [
            str(item.get("path"))
            for item in present
            if item.get("kind") == "project_identity" and item.get("engram_projects")
        ],
        "engram_config_files": len(engram),
        "mcp_configured": bool(engram),
        "engram_projects": sorted(
            {
                str(project)
                for item in present
                for project in item.get("engram_projects", [])
                if str(project).strip()
            }
        ),
        "engram_project_declarations": declarations,
        "servers_declared": servers_declared,
        "tools_declared": tools_declared,
        "observed_clients": observed_clients,
        "mcp_access_verified": False,
        "rule": "MCP configuration is declaration-only metadata; file presence does not prove usable or authorized access.",
    }


def _memory_mapping(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not isinstance(config, Mapping):
        return {}
    nested = config.get("memory")
    return nested if isinstance(nested, Mapping) else config


def _project_declarations(
    configs: Sequence[Mapping[str, Any]],
    scope: str,
) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for item in configs:
        if item.get("scope") != scope or item.get("kind") not in {
            "server_definition",
            "project_identity",
        }:
            continue
        for raw in item.get("engram_project_declarations", []):
            if isinstance(raw, Mapping) and _string_value(raw.get("project")):
                declaration = dict(raw)
                declaration["project"] = _string_value(raw.get("project"))
                declarations.append(declaration)
    return declarations


def _equivalence_index(project_equivalences: Mapping[str, str] | None) -> dict[str, str]:
    index: dict[str, str] = {}
    if not isinstance(project_equivalences, Mapping):
        return index
    for raw_identifier, raw_canonical in project_equivalences.items():
        identifier = _string_value(raw_identifier)
        canonical = _string_value(raw_canonical)
        if not identifier or not canonical:
            continue
        index[identifier.casefold()] = canonical
        index.setdefault(canonical.casefold(), canonical)
    return index


def _classify_identifiers(values: Sequence[str], equivalences: Mapping[str, str]) -> dict[str, Any]:
    identifiers: list[str] = []
    for value in values:
        if (identifier := _string_value(value)) and identifier not in identifiers:
            identifiers.append(identifier)
    identifiers.sort(key=str.casefold)
    normalized = {identifier.casefold(): identifier for identifier in identifiers}
    if not normalized:
        return {"relation": "missing", "project": None, "identifiers": []}
    if len(normalized) == 1:
        return {
            "relation": "exact",
            "project": next(iter(normalized.values())),
            "identifiers": identifiers,
        }
    if all(identifier in equivalences for identifier in normalized):
        canonical_projects = {equivalences[identifier] for identifier in normalized}
        if len(canonical_projects) == 1:
            return {
                "relation": "equivalent",
                "project": next(iter(canonical_projects)),
                "identifiers": identifiers,
            }
        return {"relation": "conflict", "project": None, "identifiers": identifiers}
    return {
        "relation": "unresolved_equivalence",
        "project": None,
        "identifiers": identifiers,
    }


def resolve_engram_project(
    memory_config: Mapping[str, Any] | None,
    configs: Sequence[Mapping[str, Any]],
    *,
    observed_project: str | None = None,
    observation_verified: bool = False,
    project_equivalences: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Reconcile per-workspace declarations without using a global fallback.

    User-scoped fixed project declarations are visible as contamination risk,
    but they never select the project for the current workspace.
    """

    memory = _memory_mapping(memory_config)
    expected = _string_value(memory.get("mcp_project"))
    workspace_declarations = _project_declarations(configs, "workspace")
    user_declarations = _project_declarations(configs, "user")
    workspace_projects = sorted({str(item["project"]) for item in workspace_declarations})
    user_projects = sorted({str(item["project"]) for item in user_declarations})
    declared_candidates = sorted(set(workspace_projects + ([expected] if expected else [])))
    observed = _string_value(observed_project)
    declaration_evidence_count = len(workspace_declarations) + (1 if expected else 0)
    equivalences = _equivalence_index(project_equivalences)
    declared_relation = _classify_identifiers(declared_candidates, equivalences)

    status = "missing"
    declared_project: str | None = None
    resolved_project: str | None = None
    if declared_relation["relation"] == "conflict":
        status = "conflict"
    elif declared_relation["relation"] == "unresolved_equivalence":
        status = "unresolved_equivalence"
    elif declared_candidates:
        declared_project = declared_relation["project"]
        if declaration_evidence_count > 1:
            status = "declared_consistent"
            resolved_project = declared_project
        else:
            status = "declared_candidate"
    elif user_projects:
        status = "global_only"

    project_identity_verified = False
    unresolved_candidates = list(declared_relation["identifiers"])
    if observed and observation_verified:
        observed_relation = _classify_identifiers([*declared_candidates, observed], equivalences)
        if observed_relation["relation"] == "conflict":
            status = "conflict"
            resolved_project = None
        elif observed_relation["relation"] == "unresolved_equivalence":
            status = "unresolved_equivalence"
            declared_project = None
            resolved_project = None
            unresolved_candidates = list(observed_relation["identifiers"])
        else:
            declared_project = observed_relation["project"]
            resolved_project = observed_relation["project"]
            status = "declared_consistent"
            project_identity_verified = True

    global_relation = "not_present"
    global_conflict = False
    global_unresolved = False
    if user_projects:
        comparison_values = [*user_projects, *declared_candidates]
        if observed and observation_verified:
            comparison_values.append(observed)
        global_classification = _classify_identifiers(comparison_values, equivalences)
        if not declared_candidates and not (observed and observation_verified):
            global_relation = "global_only"
        elif global_classification["relation"] in {"exact", "equivalent"}:
            global_relation = "consistent_with_workspace"
        elif global_classification["relation"] == "conflict":
            global_relation = "conflict"
            global_conflict = True
        else:
            global_relation = "unresolved_equivalence"
            global_unresolved = True

    return {
        "status": status,
        "expected_project": expected,
        "declared_project": declared_project,
        "resolved_project": resolved_project,
        "workspace_projects": workspace_projects,
        "user_projects": user_projects,
        "workspace_declarations": workspace_declarations,
        "user_declarations": user_declarations,
        "declared_candidates": declared_candidates,
        "declared_relation": declared_relation["relation"],
        "global_fixed_project_detected": bool(user_projects),
        "global_project_conflict": global_conflict,
        "global_project_unresolved_equivalence": global_unresolved,
        "global_project_relation": global_relation,
        "provider_observed_project": observed,
        "provider_observation_verified": bool(observed and observation_verified),
        "project_identity_verified": project_identity_verified,
        "equivalence_evidence_applied": bool(equivalences),
        "unresolved_equivalence_candidates": (
            unresolved_candidates
            if status == "unresolved_equivalence"
            else []
        ),
        "resolution_uses_global_environment": False,
        "resolution_uses_folder_name": False,
        "rule": "Resolve one workspace project from explicit per-repository and workspace-client declarations; treat differing identifiers as unresolved until registry equivalence evidence proves consistency or conflict, and never use a user/global fixed project as workspace identity.",
    }


__all__ = [
    "MCPConfigDescriptor",
    "USER_CLIENT_POLICY_CONFIGS",
    "USER_SERVER_CONFIGS",
    "WORKSPACE_CLIENT_POLICY_CONFIGS",
    "WORKSPACE_PROJECT_CONFIGS",
    "WORKSPACE_SERVER_CONFIGS",
    "config_descriptors",
    "resolve_engram_project",
    "scan_mcp_configs",
    "summarize_mcp_configs",
]
