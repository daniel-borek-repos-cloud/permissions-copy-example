# GitHub → SonarQube Cloud permission copy

`gh_to_sqc_permissions.py` reads the **direct** permissions of a GitHub repository
and applies the equivalent permissions to a SonarQube Cloud (SQC) project, using
a temporary permission template that is deleted once it has been applied.

Only the Python standard library is used — no `pip install` needed.

## Contents

| File | Purpose |
| --- | --- |
| [gh_to_sqc_permissions.py](gh_to_sqc_permissions.py) | The script |
| [role_mappings.json](role_mappings.json) | GitHub role → SQC permission mapping, the permission catalogue, and the optional admin users list |
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
   exits with status `1` without touching anything. The same response carries the
   project's **current visibility**, which is recorded so it can be restored in
   step 9.
4. **Resolve every GitHub user and team on SQC**, plus any configured
   [admin users](#admin-users-optional).
   * Each GitHub team slug (and, as a fallback, its display name) is looked up as
     an SQC group via `GET /api/user_groups/search`.
   * Each GitHub login, and each login in the optional admin users list, is looked
     up as an organization member via `GET /api/organizations/search_members`. A
     match requires the SQC login to equal the given login, or to equal it plus a
     provider suffix (`octocat@github`), both compared case-insensitively.
   The script then prints three lists: the users and groups that **will** be added
   with the exact permissions each will receive, the principals that could **not**
   be found on SQC and will be skipped, and anyone who maps to an empty permission
   list.
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
9. **Re-read the visibility and restore it if it changed.** Applying a permission
   template can reset a project's visibility to the organization's default for new
   projects, which would turn a **private project public**. The script compares the
   visibility against the value recorded in step 3 and, only if it differs, calls
   `POST /api/projects/update_visibility` to put it back, then reads it once more to
   confirm. A private project stays private and a public project stays public.
10. **Delete the temporary template** with
    `POST /api/permissions/delete_template`. Both this and the visibility check run
    in a `finally` block, so they happen even if filling in or applying the template
    fails. Pass `--keep-template` to leave the template in place for debugging.

> **Applying a permission template replaces the project's current permissions.**
> This is how SQC's `apply_template` behaves: any existing user or group permission
> on the project that is not in the template is removed. The script warns about
> this and asks for confirmation before it proceeds (skip with `--yes`).

### Visibility is preserved, not assumed

The visibility guard is deliberately a *compare-then-correct*, not a blind write:

* Recorded **before** the template is applied, from the `projects/search` response
  the script already makes — no extra API call.
* Re-read **after** applying. If it is unchanged, nothing is written.
* If it changed, the original value is restored and verified. If the restore fails,
  the script says so explicitly, tells you which visibility to set by hand, and
  exits `1` — it never reports success on a project left public by mistake.
* If SQC does not report a visibility at all, the script warns that it cannot be
  restored rather than guessing a value.

`--dry-run` performs no visibility write, and neither does a run where applying the
template failed.

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
| `architectureadmin` | Administer Architecture | Edit the project's intended architecture. Without it the architecture editor is read-only; viewing the architecture map needs no permission |
| `scan` | Execute Analysis | Run an analysis and push results to the project |
| `admin` | Administer Project | Change project configuration, permissions and settings |

These are all seven project permissions SonarQube Cloud currently accepts, per the
`permission` parameter in <https://sonarcloud.io/api/webservices/list>.

`architectureadmin` is in the catalogue but **not granted by any role** in the
default mapping, so it is available without changing current behaviour — add it to
a role's list to start granting it.

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

## Admin users (optional)

Extra users who should administer the project **regardless of what GitHub says** —
typically the people who own the SonarQube Cloud side and are not necessarily
repository collaborators. Configure them in the `admin_users` object of
[role_mappings.json](role_mappings.json):

```json
"admin_users": {
  "permissions": ["admin", "codeviewer", "user"],
  "logins": ["jsmith", "adevops@github"]
}
```

| Key | Meaning |
| --- | --- |
| `logins` | SonarQube Cloud logins. For GitHub-authenticated users this is usually the GitHub login, sometimes with a provider suffix (`jsmith@github`). Defaults to empty |
| `permissions` | What each of these users receives. Must be keys of `_sqc_permissions`. Defaults to `["admin", "codeviewer", "user"]` |

The default grants **Administer Project** (`admin`) and **See Source Code**
(`codeviewer`), plus **Browse Project** (`user`) — without `user` a person cannot
open the project in the SQC UI at all, which would make the other two useless.

### Behaviour

* **Optional.** Leave `logins` empty, or delete the whole `admin_users` object, and
  the feature is inert — nothing about a run changes.
* **Validated like any other principal.** Each login is looked up among the
  organization's members. One that does not exist on SQC is reported as skipped
  (`admin user 'ghost' — no matching SQC member`) rather than failing the run.
* **Combined, never substituted.** A login that is *also* a GitHub collaborator
  keeps both sets of permissions. The union is granted once, with no duplicate API
  calls, and the report shows the merge:

  ```
  + bob [write + admin list] -> SQC user 'bob': user, codeviewer, issueadmin, securityhotspotadmin, scan, admin
  + zoe [admin list]         -> SQC user 'zoe': admin, codeviewer, user
  ```
* **Duplicates collapse.** Repeated or case-variant logins are de-duplicated.
* **Enough on their own.** If the repository has no direct collaborators and no
  teams, a configured admin list still counts as work — the script warns that only
  the admin users will hold permissions (which removes every other permission on
  the project) and continues. With an empty admin list that same situation exits
  `1`.
* **Misconfiguration fails fast.** Listing logins while `permissions` is empty is a
  configuration error, since those users would silently be granted nothing.

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
| `1` | Project not found, no matching users/groups/admin users, or an API call failed |
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
| `GET` | `/api/projects/search` | Check the destination project exists, and read its visibility (before and after applying) |
| `GET` | `/api/user_groups/search` | Find the SQC group matching a GitHub team |
| `GET` | `/api/organizations/search_members` | Find the SQC member matching a GitHub user |
| `POST` | `/api/permissions/create_template` | Create the temporary template |
| `POST` | `/api/permissions/add_group_to_template` | Grant one permission to one group |
| `POST` | `/api/permissions/add_user_to_template` | Grant one permission to one user |
| `POST` | `/api/permissions/apply_template` | Apply the template to `PROJECT_KEY` |
| `POST` | `/api/projects/update_visibility` | Restore the original visibility — **only if applying the template changed it** |
| `POST` | `/api/permissions/delete_template` | Delete the temporary template |

Requests are sent with `Authorization: Bearer $SQC_TOKEN` and `POST` bodies are
`application/x-www-form-urlencoded`. Every call carries `organization=$SQC_ORG`
except `update_visibility`, whose only parameters are `project` and `visibility`.
`429` and `5xx` responses are retried three times with exponential backoff.

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
