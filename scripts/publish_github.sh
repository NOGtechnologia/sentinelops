#!/usr/bin/env bash
# Publish SentinelOps to GitHub (spec 17.5). NOT reversible - run only after explicit approval
# (CLAUDE.md rule 13). Always try `--dry-run` first: it runs every check and prints the commands.
#
#   scripts/publish_github.sh --owner <github-user-or-org> [--name sentinelops] [--dry-run]
#
# Requires: git, gh (authenticated: `gh auth status`), uv, pnpm, gitleaks; PostgreSQL for the tests
# (SENTINELOPS_TEST_DATABASE_URL, SENTINELOPS_E2E_ADMIN_URL).
set -euo pipefail

OWNER=""
NAME="sentinelops"
DRY_RUN=0
SKIP_CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --owner) OWNER="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-make-check) SKIP_CHECK=1; shift ;; # only meaningful together with --dry-run
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
if [ -z "$OWNER" ]; then echo "--owner is required" >&2; exit 2; fi
if [ "$SKIP_CHECK" = 1 ] && [ "$DRY_RUN" = 0 ]; then echo "--skip-make-check is only allowed with --dry-run" >&2; exit 2; fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
REPO="${OWNER}/${NAME}"
META="scripts/repo-metadata.json"
step() { printf '\n==> %s\n' "$*"; }
run() { # execute, or only print in dry-run mode
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}
json() { uv run --package sentinelops python -c "import json,sys; d=json.load(open('$META',encoding='utf-8')); print($1)"; }

# --- 1. checks ---------------------------------------------------------------------------------
step "1/6 Vorprüfungen"
if [ -n "$(git status --porcelain)" ]; then
  echo "Arbeitsbaum ist nicht sauber - bitte zuerst committen." >&2
  [ "$DRY_RUN" = 1 ] || exit 1
  echo "(dry-run: wird fortgesetzt)"
fi
for tool in git gh uv pnpm gitleaks; do
  if command -v "$tool" >/dev/null 2>&1; then echo "ok: $tool"; else
    echo "fehlt: $tool" >&2; [ "$DRY_RUN" = 1 ] || exit 1
  fi
done
if [ "$DRY_RUN" = 0 ]; then gh auth status; fi

echo "- gitleaks über die gesamte Historie"
gitleaks git --redact --no-banner -c .gitleaks.toml .
echo "- keine echten Daten (nur RFC-5737-Adressen und .example-Domains)"
uv run --package sentinelops python scripts/check_fixtures.py
echo "- Lizenz- und Community-Dateien"
for f in LICENSE NOTICE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md README.md README.en.md SUPPORT.md "$META"; do
  test -s "$f" || { echo "fehlt: $f" >&2; exit 1; }
done
echo "- Screenshots vorhanden und aktuell"
for img in dashboard queue case-overview case-timeline case-evidence entity-graph approval rules quality report; do
  for theme in dark light; do test -s "docs/images/${img}-${theme}.png" || { echo "fehlt: docs/images/${img}-${theme}.png" >&2; exit 1; }; done
done
test -s docs/images/demo.gif && test -s docs/images/social-preview.png && test -s docs/images/logo.svg
if [ -n "${SENTINELOPS_E2E_ADMIN_URL:-}" ]; then node scripts/screenshots.ts --check; else echo "(Pixelvergleich übersprungen: SENTINELOPS_E2E_ADMIN_URL nicht gesetzt - läuft in der CI)"; fi
if [ "$SKIP_CHECK" = 0 ]; then
  echo "- make check"
  uv run --package sentinelops python scripts/tasks.py check
else
  echo "(make check im Trockenlauf übersprungen)"
fi

# --- 2. confirmation ---------------------------------------------------------------------------
step "2/6 Bestätigung"
if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] Frage: Öffentliches Repository ${REPO} erstellen? [j/N]"
else
  read -r -p "Öffentliches Repository ${REPO} erstellen? [j/N] " answer
  case "$answer" in j|J|ja|Ja) ;; *) echo "Abgebrochen."; exit 1 ;; esac
fi

# --- 3. create, push, metadata -------------------------------------------------------------------
step "3/6 Repository anlegen und pushen"
PLACEHOLDER_FILES=$(git grep -l "OWNER" -- README.md README.en.md SUPPORT.md mkdocs.yml .github SECURITY.md scripts/repo-metadata.json || true)
echo "Platzhalter OWNER -> ${OWNER} in: ${PLACEHOLDER_FILES//$'\n'/ }"
if [ "$DRY_RUN" = 0 ] && [ -n "$PLACEHOLDER_FILES" ]; then
  # shellcheck disable=SC2086
  sed -i "s/OWNER/${OWNER}/g" $PLACEHOLDER_FILES
  git add -A && git commit -m "chore: set repository owner to ${OWNER}"
fi
DESCRIPTION="$(json "d['description']")"
HOMEPAGE="$(json "d['homepage']" | sed "s/OWNER/${OWNER}/")"
TOPICS="$(json "','.join(d['topics'])")"
run gh repo create "$REPO" --public --source . --remote origin --description "$DESCRIPTION" --homepage "$HOMEPAGE"
run git push -u origin main
run gh repo edit "$REPO" --add-topic "$TOPICS" --enable-discussions=false --enable-wiki=false \
  --delete-branch-on-merge --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge
echo "Social-Preview-Bild: bitte manuell hochladen (Settings -> General -> Social preview): docs/images/social-preview.png"

# --- 4. branch protection ------------------------------------------------------------------------
step "4/6 Branch-Schutz für main"
CHECKS_JSON="$(json "json.dumps([{'context': c} for c in d['branch_protection']['required_status_checks']])")"
PROTECTION=$(cat <<EOF
{"required_status_checks":{"strict":true,"checks":${CHECKS_JSON}},
 "enforce_admins":true,
 "required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true},
 "restrictions":null,
 "required_linear_history":true,
 "allow_force_pushes":false,
 "allow_deletions":false}
EOF
)
if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] gh api -X PUT repos/${REPO}/branches/main/protection --input - <<< '${PROTECTION//$'\n'/}'"
else
  printf '%s' "$PROTECTION" | gh api -X PUT "repos/${REPO}/branches/main/protection" --input -
fi

# --- 5. security features ------------------------------------------------------------------------
step "5/6 Sicherheitsfunktionen"
run gh api -X PUT "repos/${REPO}/vulnerability-alerts"
run gh api -X PUT "repos/${REPO}/automated-security-fixes"
run gh api -X PATCH "repos/${REPO}" -F "security_and_analysis[secret_scanning][status]=enabled" \
  -F "security_and_analysis[secret_scanning_push_protection][status]=enabled"
run gh api -X PUT "repos/${REPO}/private-vulnerability-reporting"
run gh api -X POST "repos/${REPO}/pages" -f "build_type=workflow"
echo "Falls ein Aufruf mangels Berechtigung scheitert: Settings -> Code security -> Dependabot alerts, Secret scanning,"
echo "Push protection, Private vulnerability reporting aktivieren; Settings -> Pages -> Source: GitHub Actions."

# --- 6. first release ----------------------------------------------------------------------------
step "6/6 Erstes Release"
echo "release-please öffnet nach dem ersten Push einen Release-PR für v1.0.0 (release-as 1.0.0)."
echo "Nach dem Merge baut release.yml die Multi-Arch-Images (GHCR), SBOM, cosign-Signatur und Attestations."
echo "Danach einmalig: Actions -> 'Visual baselines' ausführen und den PR mit den Linux-Baselines mergen."
[ "$DRY_RUN" = 1 ] && echo -e "\nTrockenlauf erfolgreich - es wurde nichts veröffentlicht."
exit 0
