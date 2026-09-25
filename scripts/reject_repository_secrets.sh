#!/usr/bin/env bash
set -Eeuo pipefail

search_root="${1:-.}"
pattern="(BEGIN ([A-Z0-9][A-Z0-9 -]{0,63} )?PRIVATE KEY|[\"']?Authorization[\"']?[[:space:]]*:[[:space:]]*[\"']?[[:space:]]*Bearer[[:space:]]+[-A-Za-z0-9._~+/]{16,}=*|[\"']?[A-Za-z0-9_-]*client[_-]?secret[\"']?[[:space:]]*[:=][[:space:]]*[^[:space:]<]+|postgres(ql)?://[^[:space:]/:@]+:[^[:space:]@/]+@|[\"']?(PGPASSWORD|DATA_SOURCE_PASS|POSTGRES(QL)?[_-]?PASSWORD|DATABASE[_-]?PASSWORD|DB[_-]?PASSWORD)[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[^[:space:]<\"']{4,}|[\"']?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"']?[[:space:]]*:[[:space:]]*[\"']?[^[:space:]<\"'\${}\[][^[:space:]<\"']{3,}|(^|[?&[:space:]])[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][[:space:]]*=[[:space:]]*[\"']?[^[:space:]&<\"'\${}]{4,})"
path_list="$(mktemp)"
trap 'rm -f -- "$path_list"' EXIT

set +e
find "$search_root" \
  \( -path "$search_root/.git" -o -path "$search_root/upstream" \) -prune -o \
  \( -type f -o -type l \) -print0 > "$path_list"
find_status=$?
set -e
if (( find_status != 0 )); then
  echo "Secret scan traversal failed (find status ${find_status})." >&2
  exit "$find_status"
fi

while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    echo "Secret scan refuses symbolic link: ${path}" >&2
    exit 2
  fi
done < "$path_list"

while IFS= read -r -d '' path; do
  set +e
  LC_ALL=C grep -aEiqz "$pattern" -- "$path"
  scan_status=$?
  set -e
  case "$scan_status" in
    0)
      echo 'Control-plane secret pattern detected.' >&2
      exit 1
      ;;
    1)
      ;;
    *)
      echo "Secret scan failed before completing (grep status ${scan_status})." >&2
      exit "$scan_status"
      ;;
  esac
done < "$path_list"
