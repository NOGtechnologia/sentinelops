"""No real data in fixtures, rules and docs (CLAUDE.md rule 10).

Text files may only contain IP addresses from documentation (RFC 5737 /
RFC 3849), private, loopback, link-local or unspecified ranges, and only the
``musterfirma.example`` domain family for company names. Third-party samples
with their own licence are listed in ALLOWED_FILES with a justification.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ("backend/tests/fixtures", "rules", "generator/src", "docs", "frontend/src", "e2e")
TEXT_SUFFIXES = {".log", ".json", ".ndjson", ".xml", ".yml", ".yaml", ".md", ".py", ".ts", ".tsx", ".txt"}
#: files with third-party content (licence and justification in docs/data-sources.md)
ALLOWED_FILES = {
    "rules/sigma/sigmahq/win_security_audit_log_cleared.yml",  # references to public URLs only
    "rules/sigma/sigmahq/lnx_privileged_user_creation.yml",
    "rules/sigma/sigmahq/win_security_user_added_to_local_administrators.yml",
}
CODE_SUFFIXES = {".py", ".ts", ".tsx"}
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN = re.compile(r"\b[a-z0-9-]+\.(?:com|de|net|org|io|co\.jp|local)\b", re.IGNORECASE)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
#: Domains that appear in documentation as references (licences, standards).
ALLOWED_DOMAINS = {
    "github.com",
    "sigmahq.io",
    "learn.microsoft.com",
    "microsoft.com",
    "attack.mitre.org",
    "mitre.org",
    "apache.org",
    "contributor-covenant.org",
    "keepachangelog.com",
    "semver.org",
    "conventionalcommits.org",
    "owasp.org",
    "rfc-editor.org",
    "ietf.org",
    "elastic.co",
    "python.org",
    "nodejs.org",
    "postgresql.org",
    "docker.com",
    "dsgvo-gesetz.de",
    "gesetze-im-internet.de",
    "bfdi.bund.de",
    "bsi.bund.de",
    "datenschutzkonferenz-online.de",
    "eur-lex.europa.eu",
    "scripts.sil.org",
    "openfontlicense.org",
    "rsms.me",
    "jetbrains.com",
    "dejavu-fonts.github.io",
    "example.com",
    "nextron-systems.com",
    "ultimatewindowssecurity.com",
    "cisecurity.org",
    "pcisecuritystandards.org",
    "nist.gov",
    "virustotal.com",
    "hybrid-analysis.com",
    "twitter.com",
    "die.net",
    "linux.die.net",
    "nhs.uk",
    "digital.nhs.uk",
    "patrick-bareiss.com",
    "keycloak.org",
    "fastapi.tiangolo.com",
    "playwright.dev",
    "vitejs.dev",
    "react.dev",
    "tanstack.com",
    "echarts.apache.org",
    "js.cytoscape.org",
    "mkdocs.org",
    "squidfunk.github.io",
    "openssf.org",
    "securityscorecards.dev",
    "pypi.org",
    "npmjs.com",
    "anthropic.com",
    "ollama.com",
    "openai.com",
    "first.org",
    "cve.org",
    "nvd.nist.gov",
    "sigstore.dev",
    "cyclonedx.org",
    "spdx.org",
    "semgrep.dev",
    "gitleaks.io",
    "aquasec.com",
    "zaproxy.org",
    "web.dev",
    "w3.org",
    "deque.com",
    "schemas.microsoft.com",
    "manifests.microsoft.com",
    "en.wikipedia.org",
    "de.wikipedia.org",
    "wikipedia.org",
    "bundesarbeitsgericht.de",
    "ec.europa.eu",
    "datatracker.ietf.org",
    "man7.org",
    "openssh.com",
    "sudo.ws",
    "linux-pam.org",
    "freedesktop.org",
    "apple.com",
    # sources cited in docs/privacy.md (legal notes) and docs/open-questions.md (name check)
    "dr-datenschutz.de",
    "haufe.de",
    "gleisslutz.com",
    "sentinelone.com",
    "justia.com",
}


def allowed_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not an address (version numbers etc.)
    if any(address in net for net in DOC_NETS):
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    )


def main() -> int:
    problems: list[str] = []
    for base in SCAN:
        directory = ROOT / base
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            rel = path.relative_to(ROOT).as_posix()
            if not path.is_file() or path.suffix not in TEXT_SUFFIXES or rel in ALLOWED_FILES:
                continue
            if "node_modules" in rel or rel.endswith(".golden.json"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            problems.extend(
                f"{rel}: non-documentation IP {m.group(0)}" for m in IP.finditer(text) if not allowed_ip(m.group(0))
            )
            if path.suffix in CODE_SUFFIXES:
                continue  # dotted identifiers (``ctx.org``) are not domains; IPs are still checked
            for match in DOMAIN.finditer(text):
                domain = match.group(0).lower()
                if not any(domain == d or domain.endswith("." + d) for d in ALLOWED_DOMAINS):
                    problems.append(f"{rel}: unexpected domain {domain}")
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"fixture check: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
