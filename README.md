# GitHub → SonarQube Cloud permission copy

`gh_to_sqc_permissions.py` reads the **direct** permissions of a GitHub repository
and applies the equivalent permissions to a SonarQube Cloud (SQC) project, using
a temporary permission template that is deleted once it has been applied.

Only the Python standard library is used — no `pip install` needed.

## Contents

| File | Purpose |
| --- | --- |
| [gh_to_sqc_permissions.py](gh_to_sqc_permissions.py) | The script |
| [role_mappings.json](role_mappings.json) | GitHub role → SQC permission mapping |
| [README.md](README.md) | This document |

## How it works

1. **Read the configuration.** All six environment variables must be set, and the
   mapping file is loaded and validated: the permissions allowed under `roles`
   are exactly the keys of the file's own `_sqc_permissions` object, so an
   unknown role or a mistyped permission is a hard error before anything is
   changed.
2. **Read direct permissions from GitHub.**
   * Users: `GET /repos/{org}/{repo}/collaborators?affiliation=direct` — the
     `direct` affiliation excludes people who only have access through a team or
     through their organization membership.
   * Teams: `GET /repos/{org}/{repo}/teams`.
   Each collaborator's `role_name` and each team's `permission` is normalised to
   one of `read`, `triage`, `write`, `maintain`, `admin`.
3. **Check the destination project on SQC** with `GET /api/projects/search`. If the
   project key does not exist in the organization, the script prints an error and
   exits with status `1` without touching anything.
4. **Resolve every GitHub user and team on SQC.**
   * Each GitHub team slug (and, as a fallback, its display name) is looked up as
     an SQC group via `GET /api/user_groups/search`.
   * Each GitHub login is looked up as an organization member via
     `GET /api/organizations/search_members`. A match requires the SQC login to
     equal the GitHub login, or to equal the GitHub login plus a provider suffix
     (`octocat@github`), both compared case-insensitively.
   The script then prints three lists: the users and groups that **will** be added
   with the exact permissions each will receive, the users and groups that exist
   on GitHub but **not** on SQC and will be skipped, and anyone whose role maps to
   an empty permission list.
5. **Exit early if there is nothing to do.** If no user and no group can be matched
   with at least one mapped permission, the script prints a message and exits with
   status `1` — no template is created.
6. **Create the temporary template** with `POST /api/permissions/create_template`,
   named `tmp-gh-sync-<project-key>-<unix-timestamp>` (override with
   `--template-name`).
7. **Fill in the template**, one API call per principal *and* permission, using
   `POST /api/permissions/add_group_to_template` and
   `POST /api/permissions/add_user_to_template`.
8. **Apply the template to the project** with
   `POST /api/permissions/apply_template`.
9. **Delete the temporary template** with
   `POST /api/permissions/delete_template`. This runs in a `finally` block, so the
   template is cleaned up even if filling it in or applying it fails. Pass
   `--keep-template` to leave it in place for debugging.

> **Applying a permission template replaces the project's current permissions.**
> This is how SQC's `apply_template` behaves: any existing user or group permission
> on the project that is not in the template is removed. The script warns about
> this and asks for confirmation before it proceeds (skip with `--yes`).

## SonarQube Cloud permissions

The permission list is **not** hard-coded in the script: it is read from the
`_sqc_permissions` object of [role_mappings.json](role_mappings.json), which is
the single source of truth. Those keys are the only values accepted under
`roles`, and each value is the permission's name in the SQC UI. The script
prints the catalogue on every run, and rejects a mapping file that has no
`_sqc_permissions` object or that uses a permission absent from it.

If SonarQube Cloud ever adds a project permission, add it to
`_sqc_permissions` and reference it under `roles` — no change to the script is
needed.

These are the values the script sends as the `permission` parameter:

| API value | Name in the SQC UI | What it allows |
| --- | --- | --- |
| `user` | Browse Project | See the project and its measures, issues and pages |
| `codeviewer` | See Source Code | View the project's source code |
| `issueadmin` | Administer Issues | Resolve, reopen, assign, change issue severity |
| `securityhotspotadmin` | Administer Security Hotspots | Change the status of a Security Hotspot |
| `scan` | Execute Analysis | Run an analysis and push results to the project |
| `admin` | Administer Project | Change project configuration, permissions and settings |

## Role mappings

GitHub roles are `Read`, `Triage`, `Write`, `Maintain` and `Admin`. The defaults
in [role_mappings.json](role_mappings.json) are:

| GitHub role | Browse (`user`) | See Source Code (`codeviewer`) | Administer Issues (`issueadmin`) | Administer Security Hotspots (`securityhotspotadmin`) | Administer (`admin`) | Execute Analysis (`scan`) |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| Read | ✅ | ✅ | | | | |
| Triage | ✅ | ✅ | | | | |
| Write | ✅ | ✅ | ✅ | ✅ | | ✅ |
| Maintain | ✅ | ✅ | ✅ | ✅ | | ✅ |
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Edit the `roles` object to change them. All five roles must be present; an empty
list is valid and means that role grants nothing on SQC, and those users and
teams are then listed as skipped.

Keys beginning with `_` hold the file's own documentation, which is how it stays
valid JSON while explaining itself. The one exception is `_sqc_permissions`,
which the script reads — see [above](#sonarqube-cloud-permissions).

## Environment variables

| Variable | Description |
| --- | --- |
| `GH_ORG` | GitHub organization that owns the repository |
| `GH_REPOSITORY` | Repository to read permissions from. Accepts `repo` or `org/repo` (the owner must then match `GH_ORG`) |
| `GH_TOKEN` | GitHub token for the API calls |
| `SQC_ORG` | SonarQube Cloud organization key containing the destination project |
| `SQC_TOKEN` | SonarQube Cloud token for the API calls |
| `PROJECT_KEY` | Key of the SQC project the template is applied to |

`MAPPINGS_FILE` is optional and sets the default mapping file path (equivalent to
`--mappings`).

### `GH_TOKEN`

Whichever token type you use, the **account it belongs to** must have write,
maintain or admin access to the repository, and must be a member of the
organization for org-owned repositories. Admin is the safe choice, since
listing teams is an administration-level read.

| Token type | What to grant |
| --- | --- |
| Fine-grained PAT (recommended) | Repository permissions **Metadata: read-only** (for `GET /collaborators`) and **Administration: read-only** (for `GET /teams`) |
| Classic PAT | Scopes **`repo`** and **`read:org`** |

**Generating a fine-grained token:** *Settings → Developer settings → Personal
access tokens → Fine-grained tokens → Generate new token*. Set **Resource owner**
to the organization in `GH_ORG` — this matters, a token owned by your personal
account cannot read an org repository's teams. Under **Repository access** pick
*Only select repositories* and choose the one repository, then set the two
permissions above and generate. If the org requires approval, the token stays
pending until an owner approves it.

Direct link: <https://github.com/settings/personal-access-tokens/new>

**Generating a classic token:** *Settings → Developer settings → Personal access
tokens → Tokens (classic) → Generate new token (classic)*, tick `repo` and
`read:org`. Classic tokens are not scoped to a single repository, so they carry
much broader access than the fine-grained equivalent — prefer fine-grained.

Direct link: <https://github.com/settings/tokens/new?scopes=repo,read:org&description=SQC%20permission%20copy>

In GitHub Actions, the built-in `secrets.GITHUB_TOKEN` works only if you grant it
the right permissions in the workflow, and it cannot read teams by default:

```yaml
permissions:
  contents: read
  # GITHUB_TOKEN cannot be granted Administration: read, so /teams will 403.
  # Use a PAT or GitHub App installation token if you need team permissions.
```

Verify a token before running the script:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $GH_TOKEN" \
  "https://api.github.com/repos/$GH_ORG/$GH_REPOSITORY/collaborators?affiliation=direct"

curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $GH_TOKEN" \
  "https://api.github.com/repos/$GH_ORG/$GH_REPOSITORY/teams"
```

Both should print `200`. A `403` on the second one means the token is missing
*Administration: read*; a `404` usually means the token cannot see the repository
at all (wrong resource owner, or the repo was not selected).

### `SQC_TOKEN`

Must belong to a user with the *Administer Organization* permission on `SQC_ORG`,
since creating, editing, applying and deleting permission templates are
organization-level administrative actions. Generate one at *My Account →
Security* in SonarQube Cloud (<https://sonarcloud.io/account/security>).

## Running it

```bash
export GH_ORG=my-github-org
export GH_REPOSITORY=my-repo
export GH_TOKEN=ghp_xxxxxxxxxxxx
export SQC_ORG=my-sqc-org
export SQC_TOKEN=squ_xxxxxxxxxxxx
export PROJECT_KEY=my-sqc-org_my-repo

# See what would happen — makes no changes:
python3 gh_to_sqc_permissions.py --dry-run

# Do it:
python3 gh_to_sqc_permissions.py
```

### Options

| Option | Effect |
| --- | --- |
| `--dry-run` | Read GitHub and SQC, print the plan, change nothing |
| `--yes` | Skip the confirmation prompt (required in CI / non-interactive shells) |
| `--mappings PATH` | Use a different mapping file (default `role_mappings.json`) |
| `--template-name NAME` | Use a specific name for the temporary template |
| `--keep-template` | Do not delete the temporary template after applying it |
| `--verbose` | Log every HTTP request that is made |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, or a completed dry run |
| `1` | Project not found, no matching users/groups, or an API call failed |
| `2` | Bad configuration — missing environment variable or invalid mapping file |
| `130` | Cancelled at the confirmation prompt, or interrupted |

## API calls

### GitHub

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/repos/{org}/{repo}` | Confirm the repository exists and is readable |
| `GET` | `/repos/{org}/{repo}/collaborators?affiliation=direct` | Users with a directly granted role |
| `GET` | `/repos/{org}/{repo}/teams` | Teams with access, and their role |

Requests are sent with `Authorization: Bearer $GH_TOKEN`,
`Accept: application/vnd.github+json` and
`X-GitHub-Api-Version: 2022-11-28`, and paginate via the `Link` header.

### SonarQube Cloud

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects/search` | Check the destination project exists |
| `GET` | `/api/user_groups/search` | Find the SQC group matching a GitHub team |
| `GET` | `/api/organizations/search_members` | Find the SQC member matching a GitHub user |
| `POST` | `/api/permissions/create_template` | Create the temporary template |
| `POST` | `/api/permissions/add_group_to_template` | Grant one permission to one group |
| `POST` | `/api/permissions/add_user_to_template` | Grant one permission to one user |
| `POST` | `/api/permissions/apply_template` | Apply the template to `PROJECT_KEY` |
| `POST` | `/api/permissions/delete_template` | Delete the temporary template |

Requests are sent with `Authorization: Bearer $SQC_TOKEN`, `POST` bodies are
`application/x-www-form-urlencoded`, and every call carries
`organization=$SQC_ORG`. `429` and `5xx` responses are retried three times with
exponential backoff.

## Notes and limitations

* **`affiliation=direct` filters *who* is listed, not *which grant* is reported.**
  GitHub documents `role_name` as "the highest role assigned to the collaborator
  after considering all sources of grants", including repository, team,
  organization and enterprise grants. So a user who holds a direct *Read* grant
  but is also in a team with *Admin* is listed (they do have a direct grant) with
  `role_name: admin`. There is no API that returns the direct grant in isolation,
  so the role copied to SQC is the user's **effective** role on the repository.
  Every collaborator is printed with the role that was read, before anything is
  applied — check that list if your organization grants access both directly and
  through teams.
* **Team access is not filtered to "direct".** GitHub's API has no
  `affiliation=direct` filter for teams, so `/repos/{org}/{repo}/teams` can also
  list a parent team whose access is inherited by a child team. Team objects do
  carry an `access_source` field (`direct`, `organization` or `enterprise`) that
  the script does not currently filter on; every team returned is reported with
  its role before anything is applied.
* **User matching is by login.** An SQC user whose login bears no relation to
  their GitHub login cannot be matched automatically and is reported as skipped.
* **Custom GitHub repository roles are not supported.** Only the five built-in
  roles are mapped; a collaborator holding a custom role is reported as skipped
  with a warning.
* **Permissions are copied, not synced.** Running the script again re-reads
  GitHub and re-applies the result; it does not track or reverse earlier runs.
