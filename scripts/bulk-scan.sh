#!/usr/bin/env bash
#
# Пакетне сканування великого списку доменів через WPGuard API.
# Ріже domains.txt на пачки по 50, запускає скан, чекає завершення,
# зберігає JSON-звіт кожної пачки у ./reports/.
#
# Використання:
#   ./scripts/bulk-scan.sh domains.txt
#
# Змінні оточення:
#   API              базовий URL бекенду           (default: http://localhost:3001)
#   CHECKS           перелік перевірок через кому  (default: plugins,endpoints,version_leak,ioc)
#   BATCH            розмір пачки, макс 50          (default: 50)
#   SCAN_BYPASS_TOKEN  токен обходу rate-limit (має збігатися з backend/.env)
#
set -euo pipefail

LIST="${1:-domains.txt}"
API="${API:-http://localhost:3001}"
CHECKS_CSV="${CHECKS:-plugins,endpoints,version_leak,ioc}"
BATCH="${BATCH:-50}"
TOKEN="${SCAN_BYPASS_TOKEN:-}"

[[ -f "$LIST" ]] || { echo "Немає файлу зі списком: $LIST" >&2; exit 1; }
command -v jq >/dev/null || { echo "Потрібен jq" >&2; exit 1; }

mkdir -p reports
CHECKS_JSON=$(printf '%s' "$CHECKS_CSV" | jq -R 'split(",")')

# нормалізований, дедуплікований список
mapfile -t ALL < <(grep -vE '^\s*(#|$)' "$LIST" | sed 's#^https\?://##; s#/*$##' | sort -u)
TOTAL=${#ALL[@]}
echo "Доменів у роботі: $TOTAL | пачка: $BATCH | перевірки: $CHECKS_CSV"

hdr=(-H 'Content-Type: application/json')
[[ -n "$TOKEN" ]] && hdr+=(-H "X-Scan-Token: $TOKEN")

batch_no=0
for ((i=0; i<TOTAL; i+=BATCH)); do
  batch_no=$((batch_no+1))
  chunk=("${ALL[@]:i:BATCH}")
  sites_json=$(printf '%s\n' "${chunk[@]}" | jq -R 'select(length>0) | "https://" + .' | jq -s .)
  body=$(jq -nc --argjson sites "$sites_json" --argjson checks "$CHECKS_JSON" \
    '{sites:$sites, checks:$checks}')

  job=$(curl -sS "${hdr[@]}" -d "$body" "$API/api/scan" | jq -r '.jobId // empty')
  [[ -n "$job" ]] || { echo "  пачка $batch_no: не вдалося створити завдання" >&2; continue; }
  echo "  пачка $batch_no: job $job (${#chunk[@]} сайтів) — чекаю…"

  while :; do
    resp=$(curl -sS "${hdr[@]}" "$API/api/jobs/$job")
    st=$(jq -r '.status' <<<"$resp")
    pr=$(jq -r '.progress // 0' <<<"$resp")
    tt=$(jq -r '.total // 0' <<<"$resp")
    printf '\r    %s %s/%s   ' "$st" "$pr" "$tt"
    [[ "$st" == completed || "$st" == error ]] && { echo; break; }
    sleep 10
  done

  curl -sS "${hdr[@]}" "$API/api/jobs/$job/export" -o "reports/batch-$(printf '%03d' "$batch_no").json"
  echo "    -> reports/batch-$(printf '%03d' "$batch_no").json"
done

# зведення по всіх пачках
echo
echo "=== Зведення ==="
jq -s '
  [.[].results[]] as $r
  | {
      сайтів:        ($r | length),
      критичних:     ([$r[] | select(.riskLevel=="critical")] | length),
      високих:       ([$r[] | select(.riskLevel=="high")]     | length),
      середніх:      ([$r[] | select(.riskLevel=="medium")]   | length),
      низьких:       ([$r[] | select(.riskLevel=="low")]      | length),
      безпечних:     ([$r[] | select(.riskLevel=="safe")]     | length),
      недоступних:   ([$r[] | select(.status=="unreachable")] | length)
    }' reports/batch-*.json

echo
echo "Топ сайтів за ризиком:"
jq -sr '
  [.[].results[]]
  | map(select(.riskLevel=="critical" or .riskLevel=="high"))
  | sort_by(.riskLevel)
  | .[] | "  [\(.riskLevel|ascii_upcase)] \(.url) — знахідок: \([.findings[]|select(.severity!="info")]|length)"
' reports/batch-*.json
