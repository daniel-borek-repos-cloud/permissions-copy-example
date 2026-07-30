#!/usr/bin/env python3
"""Copy direct GitHub repository permissions onto a SonarQube Cloud project.

The script:
  1. Reads the *direct* collaborators and teams of a GitHub repository, together
     with the role each of them holds (Read / Triage / Write / Maintain / Admin).
  2. Verifies the destination project exists on SonarQube Cloud (SQC).
  3. Resolves every GitHub user / team against SQC members / groups and reports
     which ones can be mapped and which ones will be skipped.
  4. Creates a temporary permission template, fills it in using the role ->
     permission mapping from a JSON file, applies it to the project and then
     deletes the template again.

Only the Python standard library is used.

See README.md for the full documentation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

GITHUB_API = "https://api.github.com"
SQC_API = "https://sonarcloud.io/api"

DEFAULT_MAPPINGS_FILE = "role_mappings.json"

# The permissions SonarQube Cloud accepts for a project permission template are
# not hard-coded here: they are read from the `_sqc_permissions` object of the
# mapping file, which maps each API value to its name in the SQC UI.

# GitHub exposes a repository role either as a `role_name` (collaborators) or as
# a legacy `permission` string (teams). Both are normalised to these five roles.
GITHUB_ROLES = ("read", "triage", "write", "maintain", "admin")

LEGACY_PERMISSION_TO_ROLE: dict[str, str] = {
    "pull": "read",
    "triage": "triage",
    "push": "write",
    "maintain": "maintain",
    "admin": "admin",
}


class ConfigError(Exception):
    """Raised for a bad environment / mapping file / CLI combination."""


class ApiError(Exception):
    """Raised when GitHub or SonarQube Cloud returns an error response."""


# --------------------------------------------------------------------------- #
# Terminal output helpers
# --------------------------------------------------------------------------- #

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def heading(text: str) -> None:
    print()
    print(_c(text, "1"))
    print(_c("-" * len(text), "2"))


def info(text: str) -> None:
    print(f"  {text}")


def ok(text: str) -> None:
    print(f"  {_c('+', '32')} {text}")


def skip(text: str) -> None:
    print(f"  {_c('-', '33')} {text}")


def warn(text: str) -> None:
    sys.stdout.flush()  # keep stderr in order with stdout when output is piped
    print(f"{_c('warning:', '33')} {text}", file=sys.stderr, flush=True)


def fail(text: str) -> None:
    sys.stdout.flush()
    print(f"{_c('error:', '31')} {text}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Config:
    gh_org: str
    gh_repository: str
    gh_token: str
    sqc_org: str
    sqc_token: str
    project_key: str

    @staticmethod
    def from_env() -> "Config":
        required = (
            "GH_ORG",
            "GH_REPOSITORY",
            "GH_TOKEN",
            "SQC_ORG",
            "SQC_TOKEN",
            "PROJECT_KEY",
        )
        values: dict[str, str] = {}
        missing: list[str] = []
        for name in required:
            value = (os.environ.get(name) or "").strip()
            if not value:
                missing.append(name)
            else:
                values[name] = value

        if missing:
            raise ConfigError(
                "missing required environment variable(s): " + ", ".join(missing)
            )

        repository = values["GH_REPOSITORY"]
        # Accept both "repo" and "org/repo" for convenience.
        if "/" in repository:
            owner, _, repository = repository.rpartition("/")
            if owner and owner != values["GH_ORG"]:
                raise ConfigError(
                    f"GH_REPOSITORY owner {owner!r} does not match GH_ORG "
                    f"{values['GH_ORG']!r}"
                )

        return Config(
            gh_org=values["GH_ORG"],
            gh_repository=repository,
            gh_token=values["GH_TOKEN"],
            sqc_org=values["SQC_ORG"],
            sqc_token=values["SQC_TOKEN"],
            project_key=values["PROJECT_KEY"],
        )


# --------------------------------------------------------------------------- #
# Role -> permission mappings
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Mappings:
    """The contents of the mapping file.

    `permissions` maps each SonarQube Cloud permission value to its name in the
    SQC UI, and doubles as the set of values accepted everywhere else. `roles`
    maps each GitHub repository role to the permissions it grants.
    `admin_users` is an optional list of SQC logins that receive
    `admin_user_permissions` on top of anything their GitHub role grants.
    """

    permissions: dict[str, str]
    roles: dict[str, list[str]]
    admin_users: list[str]
    admin_user_permissions: list[str]


def load_mappings(path: str) -> Mappings:
    """Load and validate the GitHub role -> SQC permission mapping file.

    The permissions that may appear under `roles` are the keys of the file's
    `_sqc_permissions` object, so the set of valid permissions lives in the
    mapping file rather than in this script.

    Other keys starting with an underscore are comments and are ignored, which
    is how the shipped file documents itself while staying valid JSON.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        raise ConfigError(f"mapping file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"mapping file {path} is not valid JSON: {exc}") from None

    if not isinstance(raw, dict):
        raise ConfigError(f"mapping file {path} must contain a JSON object")

    permissions = _parse_permission_catalogue(raw, path)
    roles = _parse_roles(raw, path, permissions)
    admin_users, admin_user_permissions = _parse_admin_users(raw, path, permissions)
    return Mappings(
        permissions=permissions,
        roles=roles,
        admin_users=admin_users,
        admin_user_permissions=admin_user_permissions,
    )


def _parse_permission_catalogue(raw: dict, path: str) -> dict[str, str]:
    """Read `_sqc_permissions` — the permissions the mapping file allows."""
    catalogue = raw.get("_sqc_permissions")
    if not isinstance(catalogue, dict) or not catalogue:
        raise ConfigError(
            f"mapping file {path} must contain a non-empty '_sqc_permissions' "
            "object listing the SonarQube Cloud permissions and their UI names"
        )

    permissions: dict[str, str] = {}
    for permission, label in catalogue.items():
        if not isinstance(permission, str) or not permission.strip():
            raise ConfigError(
                f"'_sqc_permissions' in {path} has a key that is not a "
                "non-empty string"
            )
        if not isinstance(label, str):
            raise ConfigError(
                f"'_sqc_permissions.{permission}' in {path} must be a string "
                "naming the permission as it appears in the SonarQube Cloud UI"
            )
        permissions[permission.strip()] = label.strip()
    return permissions


def _parse_roles(
    raw: dict, path: str, valid_permissions: dict[str, str]
) -> dict[str, list[str]]:
    """Read `roles`, validating each permission against the catalogue."""
    roles = raw.get("roles")
    if not isinstance(roles, dict):
        raise ConfigError(f"mapping file {path} must contain a 'roles' object")

    parsed: dict[str, list[str]] = {}
    for role, permissions in roles.items():
        if role.startswith("_"):
            continue
        normalised_role = role.strip().lower()
        if normalised_role not in GITHUB_ROLES:
            raise ConfigError(
                f"unknown GitHub role {role!r} in {path}; "
                f"expected one of: {', '.join(GITHUB_ROLES)}"
            )
        parsed[normalised_role] = _parse_permission_list(
            f"role {role!r}", permissions, path, valid_permissions
        )

    missing = [role for role in GITHUB_ROLES if role not in parsed]
    if missing:
        raise ConfigError(
            f"mapping file {path} is missing role(s): {', '.join(missing)}"
        )
    return parsed


def _parse_admin_users(
    raw: dict, path: str, valid_permissions: dict[str, str]
) -> tuple[list[str], list[str]]:
    """Read the optional `admin_users` object.

    Returns the configured logins and the permissions each of them receives.
    An absent or empty object simply disables the feature.
    """
    default_permissions = ["admin", "codeviewer", "user"]

    section = raw.get("admin_users")
    if section is None:
        return [], [p for p in default_permissions if p in valid_permissions]
    if not isinstance(section, dict):
        raise ConfigError(
            f"'admin_users' in {path} must be a JSON object with 'logins' and "
            "'permissions' keys"
        )

    raw_logins = section.get("logins", [])
    if not isinstance(raw_logins, list) or not all(
        isinstance(item, str) for item in raw_logins
    ):
        raise ConfigError(
            f"'admin_users.logins' in {path} must be a list of SonarQube Cloud "
            "logins"
        )

    logins: list[str] = []
    seen: set[str] = set()
    for login in raw_logins:
        normalised = login.strip()
        if not normalised:
            raise ConfigError(
                f"'admin_users.logins' in {path} contains an empty login"
            )
        if normalised.lower() not in seen:
            seen.add(normalised.lower())
            logins.append(normalised)

    if "permissions" in section:
        permissions = _parse_permission_list(
            "'admin_users.permissions'",
            section["permissions"],
            path,
            valid_permissions,
        )
    else:
        permissions = [p for p in default_permissions if p in valid_permissions]

    if logins and not permissions:
        raise ConfigError(
            f"'admin_users.logins' in {path} lists {len(logins)} user(s) but "
            "'admin_users.permissions' is empty, so they would be granted "
            "nothing; add permissions or empty the login list"
        )

    return logins, permissions


def _parse_permission_list(
    context: str, permissions: Any, path: str, valid_permissions: dict[str, str]
) -> list[str]:
    """Validate one list of permissions against the catalogue.

    `context` names the offending place in the file for error messages, e.g.
    "role 'write'" or "'admin_users.permissions'".
    """
    if not isinstance(permissions, list) or not all(
        isinstance(item, str) for item in permissions
    ):
        raise ConfigError(
            f"permissions for {context} in {path} must be a list of strings"
        )

    cleaned: list[str] = []
    for permission in permissions:
        normalised = permission.strip()
        if normalised not in valid_permissions:
            raise ConfigError(
                f"unknown SonarQube Cloud permission {permission!r} for "
                f"{context} in {path}; expected one of the '_sqc_permissions' "
                f"keys: {', '.join(valid_permissions)}"
            )
        if normalised not in cleaned:
            cleaned.append(normalised)
    return cleaned


# --------------------------------------------------------------------------- #
# Minimal JSON-over-HTTP client
# --------------------------------------------------------------------------- #


class HttpClient:
    def __init__(self, headers: dict[str, str], *, timeout: int = 30, verbose: bool = False):
        self._headers = headers
        self._timeout = timeout
        self._verbose = verbose

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        form: dict[str, Any] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        if params:
            query = urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None}
            )
            url = f"{url}?{query}"

        body: bytes | None = None
        headers = dict(self._headers)
        if form is not None:
            body = urllib.parse.urlencode(
                {k: v for k, v in form.items() if v is not None}
            ).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        if self._verbose:
            info(_c(f"{method} {url}", "2"))
            if form:
                redacted = {k: v for k, v in form.items() if k != "token"}
                info(_c(f"     body: {redacted}", "2"))

        request = urllib.request.Request(url, data=body, headers=headers, method=method)

        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    payload = response.read()
                    parsed = json.loads(payload) if payload.strip() else None
                    return response.status, parsed, dict(response.headers)
            except urllib.error.HTTPError as exc:
                payload = exc.read()
                # Back off on rate limiting / transient server errors.
                if exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    delay = 2 ** attempt
                    warn(f"{method} {url} returned {exc.code}; retrying in {delay}s")
                    time.sleep(delay)
                    continue
                raise ApiError(_describe_http_error(method, url, exc.code, payload)) from None
            except urllib.error.URLError as exc:
                if attempt < 3:
                    delay = 2 ** attempt
                    warn(f"{method} {url} failed ({exc.reason}); retrying in {delay}s")
                    time.sleep(delay)
                    continue
                raise ApiError(f"{method} {url} failed: {exc.reason}") from None

        raise ApiError(f"{method} {url} failed after retries")

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)[1]

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)[1]


def _describe_http_error(method: str, url: str, status: int, payload: bytes) -> str:
    detail = ""
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        detail = payload.decode("utf-8", "replace").strip()
    else:
        if isinstance(parsed, dict):
            errors = parsed.get("errors")
            if isinstance(errors, list):
                detail = "; ".join(
                    str(item.get("msg", item)) for item in errors if isinstance(item, (dict, str))
                )
            else:
                detail = str(parsed.get("message") or parsed)
        else:
            detail = str(parsed)
    detail = re.sub(r"\s+", " ", detail)[:500]
    return f"{method} {url} returned HTTP {status}" + (f": {detail}" if detail else "")


# --------------------------------------------------------------------------- #
# GitHub
# --------------------------------------------------------------------------- #


@dataclass
class GithubActor:
    """A user or team that holds a direct role on the repository."""

    identifier: str  # login for users, slug for teams
    display_name: str
    role: str

    def label(self) -> str:
        if self.display_name and self.display_name != self.identifier:
            return f"{self.identifier} ({self.display_name})"
        return self.identifier


class GithubClient:
    def __init__(self, config: Config, *, verbose: bool = False):
        self._config = config
        self._http = HttpClient(
            {
                "Authorization": f"Bearer {config.gh_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "gh-to-sqc-permissions",
            },
            verbose=verbose,
        )

    def _paginate(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict]:
        url = f"{GITHUB_API}{path}"
        query: dict[str, Any] | None = dict(params or {})
        query["per_page"] = 100
        while url:
            status, payload, headers = self._http.request("GET", url, params=query)
            query = None  # subsequent URLs come fully formed from the Link header
            if isinstance(payload, list):
                yield from (item for item in payload if isinstance(item, dict))
            url = _next_link(headers.get("Link") or headers.get("link"))

    def check_repository(self) -> dict:
        repo = self._http.get(
            f"{GITHUB_API}/repos/{self._config.gh_org}/{self._config.gh_repository}"
        )
        if not isinstance(repo, dict):
            raise ApiError("unexpected response when reading the repository")
        return repo

    def direct_collaborators(self) -> list[GithubActor]:
        """Users with a permission granted directly on the repository.

        `affiliation=direct` excludes users who only have access through a team
        or through their organization membership.
        """
        actors: list[GithubActor] = []
        for user in self._paginate(
            f"/repos/{self._config.gh_org}/{self._config.gh_repository}/collaborators",
            {"affiliation": "direct"},
        ):
            login = user.get("login")
            if not login:
                continue
            role = _normalise_role(user.get("role_name") or user.get("permission"))
            if role is None:
                warn(
                    f"skipping collaborator {login}: unrecognised role "
                    f"{user.get('role_name') or user.get('permission')!r}"
                )
                continue
            actors.append(
                GithubActor(identifier=login, display_name=user.get("name") or "", role=role)
            )
        return actors

    def teams(self) -> list[GithubActor]:
        """Teams that have access to the repository.

        GitHub has no `affiliation=direct` filter for teams, so this can also
        return parent teams whose access is inherited by children. Each team is
        reported with the role GitHub resolves for the repository.
        """
        actors: list[GithubActor] = []
        for team in self._paginate(
            f"/repos/{self._config.gh_org}/{self._config.gh_repository}/teams"
        ):
            slug = team.get("slug") or team.get("name")
            if not slug:
                continue
            role = _normalise_role(team.get("permission")) or _role_from_permissions(
                team.get("permissions")
            )
            if role is None:
                warn(
                    f"skipping team {slug}: unrecognised permission "
                    f"{team.get('permission')!r}"
                )
                continue
            actors.append(
                GithubActor(
                    identifier=slug, display_name=team.get("name") or "", role=role
                )
            )
        return actors


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        if 'rel="next"' in section[1].replace(" ", "").replace("'", '"'):
            return section[0].strip().strip("<>")
    return None


def _normalise_role(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if candidate in GITHUB_ROLES:
        return candidate
    return LEGACY_PERMISSION_TO_ROLE.get(candidate)


def _role_from_permissions(permissions: Any) -> str | None:
    """Derive a role from GitHub's boolean `permissions` object."""
    if not isinstance(permissions, dict):
        return None
    for key, role in (
        ("admin", "admin"),
        ("maintain", "maintain"),
        ("push", "write"),
        ("triage", "triage"),
        ("pull", "read"),
    ):
        if permissions.get(key):
            return role
    return None


# --------------------------------------------------------------------------- #
# SonarQube Cloud
# --------------------------------------------------------------------------- #


class SqcClient:
    def __init__(self, config: Config, *, verbose: bool = False):
        self._config = config
        self._http = HttpClient(
            {
                "Authorization": f"Bearer {config.sqc_token}",
                "Accept": "application/json",
                "User-Agent": "gh-to-sqc-permissions",
            },
            verbose=verbose,
        )
        self._org = config.sqc_org

    @property
    def project_key(self) -> str:
        return self._config.project_key

    # -- lookups ---------------------------------------------------------- #

    def find_project(self) -> dict | None:
        """Return the project component, including its `visibility`, or None."""
        payload = self._http.get(
            f"{SQC_API}/projects/search",
            params={"organization": self._org, "projects": self._config.project_key},
        )
        components = (payload or {}).get("components") or []
        for component in components:
            if component.get("key") == self._config.project_key:
                return component
        return None

    def project_visibility(self) -> str | None:
        """Read the project's current visibility ('private' or 'public')."""
        project = self.find_project()
        visibility = (project or {}).get("visibility")
        return visibility if isinstance(visibility, str) else None

    def find_group(self, name: str) -> str | None:
        """Return the exact SQC group name matching `name`, if any."""
        for group in self._search(
            f"{SQC_API}/user_groups/search", "groups", {"organization": self._org, "q": name}
        ):
            group_name = group.get("name")
            if isinstance(group_name, str) and group_name.lower() == name.lower():
                return group_name
        return None

    def find_user(self, login: str) -> str | None:
        """Return the SQC login of the org member matching a GitHub login."""
        target = login.lower()
        for member in self._search(
            f"{SQC_API}/organizations/search_members",
            "users",
            {"organization": self._org, "q": login},
        ):
            sqc_login = member.get("login")
            if not isinstance(sqc_login, str):
                continue
            candidate = sqc_login.lower()
            # SQC logins for GitHub-authenticated users are usually the GitHub
            # login, sometimes suffixed with the identity provider.
            if candidate == target or candidate.split("@")[0] == target:
                return sqc_login
        return None

    def _search(self, url: str, key: str, params: dict[str, Any]) -> Iterator[dict]:
        page = 1
        while True:
            payload = self._http.get(
                url, params={**params, "p": page, "ps": 100}
            ) or {}
            items = payload.get(key) or []
            for item in items:
                if isinstance(item, dict):
                    yield item
            paging = payload.get("paging") or {}
            total = paging.get("total")
            page_size = paging.get("pageSize") or 100
            if not items or total is None or page * page_size >= total:
                return
            page += 1

    # -- template management ---------------------------------------------- #

    def create_template(self, name: str, description: str) -> str:
        payload = self._http.post(
            f"{SQC_API}/permissions/create_template",
            form={"organization": self._org, "name": name, "description": description},
        )
        template = (payload or {}).get("permissionTemplate") or {}
        template_name = template.get("name") or name
        return template_name

    def add_user_to_template(self, template_name: str, login: str, permission: str) -> None:
        self._http.post(
            f"{SQC_API}/permissions/add_user_to_template",
            form={
                "organization": self._org,
                "templateName": template_name,
                "login": login,
                "permission": permission,
            },
        )

    def add_group_to_template(
        self, template_name: str, group_name: str, permission: str
    ) -> None:
        self._http.post(
            f"{SQC_API}/permissions/add_group_to_template",
            form={
                "organization": self._org,
                "templateName": template_name,
                "groupName": group_name,
                "permission": permission,
            },
        )

    def apply_template(self, template_name: str) -> None:
        self._http.post(
            f"{SQC_API}/permissions/apply_template",
            form={
                "organization": self._org,
                "templateName": template_name,
                "projectKey": self._config.project_key,
            },
        )

    def delete_template(self, template_name: str) -> None:
        self._http.post(
            f"{SQC_API}/permissions/delete_template",
            form={"organization": self._org, "templateName": template_name},
        )

    # -- visibility -------------------------------------------------------- #

    def update_visibility(self, visibility: str) -> None:
        """Set the project's visibility.

        This endpoint takes only `project` and `visibility` — it has no
        `organization` parameter.
        """
        self._http.post(
            f"{SQC_API}/projects/update_visibility",
            form={"project": self._config.project_key, "visibility": visibility},
        )


# --------------------------------------------------------------------------- #
# Resolution + reporting
# --------------------------------------------------------------------------- #


ADMIN_LIST_SOURCE = "admin list"


@dataclass
class Resolved:
    """One SQC user or group and the permissions it will be granted."""

    label: str  # how the principal is shown in the report
    source: str  # the GitHub role it came from, or "admin list"
    sqc_name: str
    permissions: list[str]

    @staticmethod
    def from_actor(
        actor: GithubActor, sqc_name: str, permissions: list[str]
    ) -> "Resolved":
        return Resolved(
            label=actor.label(),
            source=actor.role,
            sqc_name=sqc_name,
            permissions=list(permissions),
        )

    def merge(self, source: str, permissions: Iterable[str]) -> None:
        """Add another grant for the same principal, keeping the union."""
        if source not in self.source.split(" + "):
            self.source = f"{self.source} + {source}"
        for permission in permissions:
            if permission not in self.permissions:
                self.permissions.append(permission)


@dataclass
class Plan:
    users: list[Resolved] = field(default_factory=list)
    groups: list[Resolved] = field(default_factory=list)
    missing_users: list[GithubActor] = field(default_factory=list)
    missing_groups: list[GithubActor] = field(default_factory=list)
    missing_admin_users: list[str] = field(default_factory=list)
    unmapped: list[Resolved] = field(default_factory=list)

    def has_work(self) -> bool:
        return bool(self.users or self.groups)


def build_plan(
    sqc: SqcClient,
    collaborators: Iterable[GithubActor],
    teams: Iterable[GithubActor],
    mappings: Mappings,
) -> Plan:
    plan = Plan()

    # Keyed by SQC login so that a collaborator who is also on the admin list
    # ends up with the union of both grants rather than two competing entries.
    by_login: dict[str, Resolved] = {}
    _resolve_collaborators(sqc, collaborators, mappings, plan, by_login)
    _resolve_admin_users(sqc, mappings, plan, by_login)

    for resolved in by_login.values():
        _file_resolved(plan, resolved, plan.users)

    _resolve_teams(sqc, teams, mappings, plan)
    return plan


def _file_resolved(plan: Plan, resolved: Resolved, bucket: list[Resolved]) -> None:
    """Put a resolved principal in its bucket, or in `unmapped` if it gets nothing."""
    if resolved.permissions:
        bucket.append(resolved)
    else:
        plan.unmapped.append(resolved)


def _resolve_collaborators(
    sqc: SqcClient,
    collaborators: Iterable[GithubActor],
    mappings: Mappings,
    plan: Plan,
    by_login: dict[str, Resolved],
) -> None:
    for actor in collaborators:
        permissions = mappings.roles.get(actor.role, [])
        sqc_login = sqc.find_user(actor.identifier)
        if sqc_login is None:
            plan.missing_users.append(actor)
            continue
        existing = by_login.get(sqc_login.lower())
        if existing is None:
            by_login[sqc_login.lower()] = Resolved.from_actor(
                actor, sqc_login, permissions
            )
        else:
            existing.merge(actor.role, permissions)


def _resolve_admin_users(
    sqc: SqcClient,
    mappings: Mappings,
    plan: Plan,
    by_login: dict[str, Resolved],
) -> None:
    """Add the configured admin users, merging with their GitHub role if any."""
    for login in mappings.admin_users:
        sqc_login = sqc.find_user(login)
        if sqc_login is None:
            plan.missing_admin_users.append(login)
            continue
        existing = by_login.get(sqc_login.lower())
        if existing is None:
            by_login[sqc_login.lower()] = Resolved(
                label=login,
                source=ADMIN_LIST_SOURCE,
                sqc_name=sqc_login,
                permissions=list(mappings.admin_user_permissions),
            )
        else:
            existing.merge(ADMIN_LIST_SOURCE, mappings.admin_user_permissions)


def _resolve_teams(
    sqc: SqcClient,
    teams: Iterable[GithubActor],
    mappings: Mappings,
    plan: Plan,
) -> None:
    for actor in teams:
        permissions = mappings.roles.get(actor.role, [])
        group_name = sqc.find_group(actor.identifier)
        if group_name is None and actor.display_name:
            group_name = sqc.find_group(actor.display_name)
        if group_name is None:
            plan.missing_groups.append(actor)
            continue
        _file_resolved(
            plan, Resolved.from_actor(actor, group_name, permissions), plan.groups
        )


def _print_resolved(title: str, kind: str, items: list[Resolved]) -> None:
    heading(title)
    if not items:
        info("(none)")
        return
    for item in items:
        ok(
            f"{item.label} [{item.source}] -> SQC {kind} "
            f"'{item.sqc_name}': {', '.join(item.permissions)}"
        )


def print_plan(plan: Plan) -> None:
    _print_resolved("Users to add to the permission template", "user", plan.users)
    _print_resolved("Groups to add to the permission template", "group", plan.groups)

    if plan.missing_users or plan.missing_groups or plan.missing_admin_users:
        heading("Skipped: not found on SonarQube Cloud")
        for actor in plan.missing_users:
            skip(f"user {actor.label()} [{actor.role}] - no matching SQC member")
        for actor in plan.missing_groups:
            skip(f"team {actor.label()} [{actor.role}] - no matching SQC group")
        for login in plan.missing_admin_users:
            skip(
                f"admin user '{login}' [{ADMIN_LIST_SOURCE}] - no matching SQC "
                "member; check the login in the mapping file"
            )

    if plan.unmapped:
        heading("Skipped: maps to no SonarQube Cloud permission")
        for item in plan.unmapped:
            skip(f"{item.label} [{item.source}] -> '{item.sqc_name}'")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy direct GitHub repository permissions to a SonarQube Cloud "
            "project via a temporary permission template."
        )
    )
    parser.add_argument(
        "--mappings",
        default=os.environ.get("MAPPINGS_FILE", DEFAULT_MAPPINGS_FILE),
        help=f"path to the role mapping JSON file (default: {DEFAULT_MAPPINGS_FILE})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be done without creating or applying a template",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="do not ask for confirmation before applying the template",
    )
    parser.add_argument(
        "--keep-template",
        action="store_true",
        help="do not delete the temporary template after applying it (for debugging)",
    )
    parser.add_argument(
        "--template-name",
        help="override the generated name of the temporary permission template",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log every HTTP request that is made",
    )
    return parser.parse_args(argv)


def temporary_template_name(project_key: str, override: str | None) -> str:
    if override:
        return override
    stem = re.sub(r"[^A-Za-z0-9_.\-]+", "-", project_key).strip("-")[:60]
    return f"tmp-gh-sync-{stem}-{int(time.time())}"


def confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        fail("cannot ask for confirmation on a non-interactive terminal; use --yes")
        return False
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def _print_configuration(
    config: Config, args: argparse.Namespace, mappings: Mappings
) -> None:
    heading("Configuration")
    info(f"GitHub repository : {config.gh_org}/{config.gh_repository}")
    info(f"SQC organization  : {config.sqc_org}")
    info(f"SQC project key   : {config.project_key}")
    info(f"Mapping file      : {args.mappings}")

    heading("SonarQube Cloud permissions defined in the mapping file")
    for permission, label in mappings.permissions.items():
        info(f"{permission:<21} -> {label}")

    heading("Role mappings")
    for role in GITHUB_ROLES:
        permissions = mappings.roles[role]
        rendered = ", ".join(permissions) if permissions else "(no permissions)"
        info(f"{role.capitalize():<9} -> {rendered}")

    heading("Admin users (optional, from the mapping file)")
    if mappings.admin_users:
        info(f"Granted: {', '.join(mappings.admin_user_permissions)}")
        for login in mappings.admin_users:
            info(f"  {login}")
    else:
        info("(none configured)")


def _print_actors(label: str, actors: list[GithubActor]) -> None:
    info(f"{label}: {len(actors)}")
    for actor in actors:
        info(f"  {actor.label()} [{actor.role}]")


def run(args: argparse.Namespace) -> int:
    config = Config.from_env()
    mappings = load_mappings(args.mappings)

    _print_configuration(config, args, mappings)

    github = GithubClient(config, verbose=args.verbose)
    sqc = SqcClient(config, verbose=args.verbose)

    heading("Reading direct permissions from GitHub")
    github.check_repository()
    collaborators = github.direct_collaborators()
    teams = github.teams()
    _print_actors("Direct collaborators", collaborators)
    _print_actors("Teams with access", teams)

    # Configured admin users are work in their own right, so an empty GitHub
    # side is only fatal when the admin list is empty too.
    if not collaborators and not teams and not mappings.admin_users:
        fail(
            f"{config.gh_org}/{config.gh_repository} has no direct collaborators and "
            "no teams, and no admin users are configured in the mapping file; "
            "nothing to copy."
        )
        return 1
    if not collaborators and not teams:
        warn(
            f"{config.gh_org}/{config.gh_repository} has no direct collaborators "
            "and no teams; only the configured admin users will be granted "
            "permissions, which removes every other permission on the project."
        )

    heading("Checking the destination project on SonarQube Cloud")
    project = sqc.find_project()
    if project is None:
        fail(
            f"project '{config.project_key}' was not found in SonarQube Cloud "
            f"organization '{config.sqc_org}'."
        )
        return 1
    ok(f"found '{project.get('name') or config.project_key}' ({config.project_key})")

    original_visibility = project.get("visibility")
    if isinstance(original_visibility, str):
        ok(f"current visibility: {original_visibility} (will be preserved)")
    else:
        original_visibility = None
        warn(
            "SonarQube Cloud did not report the project's visibility, so it "
            "cannot be checked or restored after the template is applied."
        )

    heading("Resolving users, teams and admin users on SonarQube Cloud")
    info("Looking up each collaborator, team and configured admin user...")
    plan = build_plan(sqc, collaborators, teams, mappings)
    print_plan(plan)

    if not plan.has_work():
        print()
        fail(
            "none of the GitHub users or teams, and none of the configured admin "
            "users, could be matched to a SonarQube Cloud member or group with at "
            "least one mapped permission; no permission template will be created."
        )
        return 1

    permission_count = sum(len(item.permissions) for item in plan.users) + sum(
        len(item.permissions) for item in plan.groups
    )

    heading("Summary")
    info(
        f"{len(plan.users)} user(s) and {len(plan.groups)} group(s), "
        f"{permission_count} permission grant(s)"
    )
    skipped = (
        len(plan.missing_users)
        + len(plan.missing_groups)
        + len(plan.missing_admin_users)
    )
    info(
        f"{skipped} principal(s) will be skipped "
        f"({len(plan.missing_users)} user, {len(plan.missing_groups)} group, "
        f"{len(plan.missing_admin_users)} admin user)"
    )

    if args.dry_run:
        print()
        ok("dry run: no permission template was created, applied or deleted.")
        return 0

    print()
    warn(
        f"applying a permission template replaces the existing permissions of "
        f"'{config.project_key}'."
    )
    if original_visibility:
        info(
            f"visibility will be checked afterwards and kept at "
            f"'{original_visibility}'."
        )
    if not args.yes and not confirm(
        f"Apply these permissions to '{config.project_key}'?"
    ):
        info("aborted; nothing was changed.")
        return 130

    exit_code = apply_permissions(
        sqc, config, args, plan, original_visibility=original_visibility
    )

    if exit_code == 0:
        print()
        ok(
            f"GitHub permissions of {config.gh_org}/{config.gh_repository} were "
            f"applied to '{config.project_key}'."
        )
    return exit_code


def apply_permissions(
    sqc: SqcClient,
    config: Config,
    args: argparse.Namespace,
    plan: Plan,
    *,
    original_visibility: str | None,
) -> int:
    """Create the temporary template, apply it, then clean up.

    The template is deleted and the project's visibility is restored even if
    filling in or applying the template fails.
    """
    template_name = temporary_template_name(config.project_key, args.template_name)

    heading("Creating the temporary permission template")
    created = sqc.create_template(
        template_name,
        description=(
            f"Temporary template mirroring GitHub permissions of "
            f"{config.gh_org}/{config.gh_repository}. Safe to delete."
        ),
    )
    ok(f"created template '{created}'")

    exit_code = 0
    applied = False
    try:
        heading("Filling in the template")
        _fill_template(sqc, created, plan)

        heading("Applying the template to the project")
        applied = True
        sqc.apply_template(created)
        ok(f"applied '{created}' to '{config.project_key}'")
    except ApiError as exc:
        fail(str(exc))
        exit_code = 1
    finally:
        if applied:
            exit_code = _restore_visibility(sqc, original_visibility) or exit_code
        exit_code = _remove_template(sqc, created, args.keep_template) or exit_code

    return exit_code


def _fill_template(sqc: SqcClient, template_name: str, plan: Plan) -> None:
    for item in plan.groups:
        for permission in item.permissions:
            sqc.add_group_to_template(template_name, item.sqc_name, permission)
            ok(f"group '{item.sqc_name}' + {permission}")
    for item in plan.users:
        for permission in item.permissions:
            sqc.add_user_to_template(template_name, item.sqc_name, permission)
            ok(f"user '{item.sqc_name}' + {permission}")


def _restore_visibility(sqc: SqcClient, original: str | None) -> int:
    """Put the project's visibility back if applying the template changed it.

    Applying a permission template can reset a project's visibility to the
    organization's default for new projects, which would make a private project
    public. The visibility read before the template was applied is authoritative.
    """
    heading("Checking the project's visibility")
    if original is None:
        warn("the original visibility is unknown, so it cannot be restored.")
        return 0

    try:
        current = sqc.project_visibility()
    except ApiError as exc:
        fail(f"could not read the project's visibility back: {exc}")
        warn(f"check in SonarQube Cloud that the project is still {original}.")
        return 1

    if current == original:
        ok(f"still {original}; unchanged")
        return 0

    warn(
        f"applying the template changed the visibility from {original} to "
        f"{current}; restoring {original}."
    )
    try:
        sqc.update_visibility(original)
    except ApiError as exc:
        fail(f"could not restore the project's visibility to {original}: {exc}")
        warn(f"set '{sqc.project_key}' back to {original} in SonarQube Cloud now.")
        return 1

    verified = None
    try:
        verified = sqc.project_visibility()
    except ApiError:
        pass  # the restore call itself succeeded; the read-back is a courtesy
    if verified is not None and verified != original:
        fail(f"visibility is {verified} after restoring it to {original}.")
        return 1
    ok(f"restored to {original}")
    return 0


def _remove_template(sqc: SqcClient, template_name: str, keep: bool) -> int:
    if keep:
        heading("Temporary template kept")
        info(f"'{template_name}' was left in place (--keep-template)")
        return 0

    heading("Deleting the temporary permission template")
    try:
        sqc.delete_template(template_name)
    except ApiError as exc:
        fail(f"could not delete the temporary template '{template_name}': {exc}")
        warn("delete it manually in SonarQube Cloud to avoid clutter.")
        return 1
    ok(f"deleted template '{template_name}'")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return run(args)
    except ConfigError as exc:
        fail(str(exc))
        return 2
    except ApiError as exc:
        fail(str(exc))
        return 1
    except KeyboardInterrupt:
        print()
        fail("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
