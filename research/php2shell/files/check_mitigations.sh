#!/usr/bin/env bash
# check_mitigations.sh — verify CVE-2026-109618 / 109619 posture on a LOCAL host.
# Run on the PHP server itself. Reports version + interim-mitigation state for
# both CVEs (they share the same fixed builds).
#
# Exit code reflects PATCH status plus the 109619 trigger toggles (which are
# clean on/off settings). 109618 has no single safe value, so its settings are
# reported as hardening guidance and do not change the exit code.
#   0 = patched   1 = affected   2 = php not found   3 = affected, 619 paths off
set -u

fixed_for () { case "$1" in 8.2) echo 8.2.35;; 8.3) echo 8.3.36;;
  8.4) echo 8.4.27;; 8.5) echo 8.5.12;; *) echo "";; esac; }

command -v php >/dev/null 2>&1 || { echo "php not found in PATH"; exit 2; }

ver="$(php -r 'echo PHP_VERSION;')"
branch="$(printf '%s' "$ver" | cut -d. -f1,2)"
fixed="$(fixed_for "$branch")"

echo "CVE-2026-109618 / 109619 mitigation check"
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

# --- 109619 trigger paths (clean on/off toggles) ------------------------------
up="$(php -r 'echo ini_get("session.upload_progress.enabled")?"On":"Off";')"
feb="$(php -r 'echo ($x=ini_get("fatal_error_backtraces"))===false?"n/a":($x?"On":"Off");')"
echo
echo "  109619 — stale global state:"
echo "    session.upload_progress.enabled : $up"
echo "    fatal_error_backtraces          : $feb"

# --- 109618 trigger surface (OOM during input processing) ---------------------
ml="$(php -r 'echo ini_get("memory_limit");')"
pms="$(php -r 'echo ini_get("post_max_size");')"
miv="$(php -r 'echo ini_get("max_input_vars");')"
minl="$(php -r 'echo ini_get("max_input_nesting_level");')"
mfu="$(php -r 'echo ini_get("max_file_uploads");')"
mbp="$(php -r 'echo ($x=ini_get("max_multipart_body_parts"))===false?"n/a":$x;')"
echo
echo "  109618 — OOM corruption (hardening, not an on/off fix):"
echo "    memory_limit             : $ml   (advisory: -1 is the primary config mitigation, still incomplete)"
echo "    post_max_size            : $pms"
echo "    max_input_vars           : $miv"
echo "    max_input_nesting_level  : $minl"
echo "    max_file_uploads         : $mfu"
echo "    max_multipart_body_parts : $mbp"
[ "$ml" != "-1" ] && echo "    note: do NOT cap memory with RLIMIT_AS/RLIMIT_DATA — that triggers the 109618 path."

if [ "$verdict" = "patched" ]; then exit 0; fi

# affected: report interim mitigation coverage for the 619 toggles
echo
echo "  Interim mitigations (NOT a substitute for patching):"
mitigated=1
[ "$up" = "On" ]  && { echo "   - 109619: set session.upload_progress.enabled=0"; mitigated=0; }
[ "$feb" = "On" ] && { echo "   - 109619: set fatal_error_backtraces=0 and restart ALL workers"; mitigated=0; }
echo "   - 109618: set memory_limit=-1, keep post_max_size tight, and cap"
echo "            max_input_vars / max_input_nesting_level / max_file_uploads."
[ "$mitigated" -eq 1 ] && { echo "   - 109619 trigger paths already disabled; still UPGRADE."; exit 3; }
exit 1
