#!/usr/bin/env bash
# check_mitigations.sh — verify CVE-2026-109619 posture on a LOCAL host.
# Run on the PHP server itself. Reports version + interim-mitigation state.
# Exit: 0 = patched  1 = affected  3 = affected but interim mitigations set
set -u

fixed_for () { case "$1" in 8.2) echo 8.2.35;; 8.3) echo 8.3.36;;
  8.4) echo 8.4.27;; 8.5) echo 8.5.12;; *) echo "";; esac; }

command -v php >/dev/null 2>&1 || { echo "php not found in PATH"; exit 2; }

ver="$(php -r 'echo PHP_VERSION;')"
branch="$(printf '%s' "$ver" | cut -d. -f1,2)"
fixed="$(fixed_for "$branch")"

echo "CVE-2026-109619 mitigation check"
echo "  PHP version : $ver"
if [ -z "$fixed" ]; then
  echo "  Branch $branch has no/limited upstream fix — EXPOSED, plan upgrade."
  verdict=affected
# ver >= fixed  <=>  the smaller of {fixed,ver} is fixed.
elif [ "$(printf '%s\n%s\n' "$fixed" "$ver" | sort -V | head -1)" = "$fixed" ]; then
  echo "  Fixed in    : $fixed  ->  PATCHED ✅"
  verdict=patched
else
  echo "  Fixed in    : $fixed  ->  AFFECTED ❌ (upgrade is the only full fix)"
  verdict=affected
fi

up="$(php -r 'echo ini_get("session.upload_progress.enabled")?"On":"Off";')"
feb="$(php -r 'echo ($x=ini_get("fatal_error_backtraces"))===false?"n/a":($x?"On":"Off");')"
echo "  session.upload_progress.enabled : $up"
echo "  fatal_error_backtraces          : $feb"

if [ "$verdict" = "patched" ]; then exit 0; fi

# affected: report interim mitigation coverage
echo
echo "  Interim mitigations (NOT a substitute for patching):"
mitigated=1
[ "$up" = "On" ]  && { echo "   - set session.upload_progress.enabled=0"; mitigated=0; }
[ "$feb" = "On" ] && { echo "   - set fatal_error_backtraces=0 and restart ALL workers"; mitigated=0; }
[ "$mitigated" -eq 1 ] && { echo "   - trigger paths already disabled; still UPGRADE."; exit 3; }
exit 1
