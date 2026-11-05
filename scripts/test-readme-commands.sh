#!/bin/sh
# Execute the two documented one-liners with a controlled download boundary.
# A failed/partial download must never execute; temp scripts must be removed.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir "$WORK/bin"
export RUN_MARKER="$WORK/executed" CURL_TARGET="$WORK/target" CURL_URL="$WORK/url"
# Попытка через проводник на VPS (--proxy) пишется в GATE_LOG; GATE_FAIL=1
# роняет только её, DOWNLOAD_FAIL=1 — любую загрузку.
export GATE_LOG="$WORK/gate"
cat > "$WORK/bin/curl" <<'EOF'
#!/bin/sh
proxy=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) shift; target=$1 ;;
        --proxy) shift; proxy=$1 ;;
        https://*) printf '%s\n' "$1" > "$CURL_URL" ;;
    esac
    shift
done
printf '%s\n' "$target" > "$CURL_TARGET"
printf 'printf "executed:%%s\\n" "${D2K_REF:-unset}" >> "$RUN_MARKER"\n' > "$target"
if [ -n "$proxy" ]; then
    printf '%s\n' "$proxy" >> "$GATE_LOG"
    [ "${GATE_FAIL:-0}" = 0 ] || exit 7
fi
[ "${DOWNLOAD_FAIL:-0}" = 0 ] || exit 22
EOF
chmod +x "$WORK/bin/curl"
cat > "$WORK/bin/wget" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
    case "$1" in
        -O) shift; target=$1 ;;
        https://*) printf '%s\n' "$1" > "$CURL_URL" ;;
    esac
    shift
done
printf '%s\n' "$target" > "$CURL_TARGET"
printf 'printf "executed:%%s\\n" "${D2K_REF:-unset}" >> "$RUN_MARKER"\n' > "$target"
[ "${DOWNLOAD_FAIL:-0}" = 0 ] || exit 1
EOF
chmod +x "$WORK/bin/wget"
export PATH="$WORK/bin:$PATH"

# КОМАНДЫ ИЩУТСЯ ПО СОДЕРЖИМОМУ, А НЕ ПО НОМЕРУ БЛОКА. Прежняя редакция брала
# первый и второй блок ```sh и считала их curl-установкой и curl-удалением.
# Это держалось на порядке разделов README и сломалось, как только установка
# OpenWrt встала вторым блоком. Требование же не про порядок: КАЖДАЯ
# документированная однострочная команда обязана запускаться, отвергать
# неполную загрузку и убирать за собой временный файл. Теперь проверяются все
# четыре — curl и wget, установка и удаление, — и порядок разделов свободен.
#
# 14.10.2026: команда одна для Keenetic и OpenWrt — curl (на OpenWrt он
# ставится на шаге подготовки через VPS проекта). Вариант с wget убран
# сознательно: uclient-fetch шлёт прокси «GET https://…» вместо CONNECT, и
# пройти через VPS со сквозным TLS он не может. Требования те же — запуск,
# отказ от неполной загрузки, уборка, — плюс новое: сперва через проводник
# на VPS, при его отказе напрямую.
block_for() {   # $1 — загрузчик (curl|wget), $2 — скрипт (install|uninstall)
    awk -v tool="$1" -v want="$2" '
        /^```sh$/ { getline; if ($0 ~ tool " " && $0 ~ "/" want "\\.sh") { print; exit } }
    ' "$ROOT/README.md"
}

tool=curl
    for script in install uninstall; do
        command=$(block_for "$tool" "$script")
        [ -n "$command" ] || { echo "в README нет команды: $tool $script" >&2; exit 1; }
        case "$command" in
            *"$tool"*) ;;
            *) echo "команда $tool $script использует не тот загрузчик" >&2; exit 1 ;;
        esac
        sh -n -c "$command"
        rm -f "$RUN_MARKER"
        if DOWNLOAD_FAIL=1 sh -c "$command"; then
            echo "неудачная загрузка вернула успех: $tool $script" >&2; exit 1
        fi
        [ ! -e "$RUN_MARKER" ] || { echo "частичная загрузка исполнена: $tool $script" >&2; exit 1; }
        [ ! -e "$(cat "$CURL_TARGET")" ] || { echo "неудачная загрузка оставила файл: $tool $script" >&2; exit 1; }
        DOWNLOAD_FAIL=0 sh -c "$command"
        [ -s "$RUN_MARKER" ]
        [ ! -e "$(cat "$CURL_TARGET")" ]
        [ "$(cat "$CURL_URL")" = "https://raw.githubusercontent.com/punisher89/d2p/fix/detect-accuracy-20261105/scripts/$script.sh" ] \
            || { echo "команда $tool $script тянет не тот адрес" >&2; exit 1; }
        if [ "$script" = install ]; then
            [ "$(cat "$RUN_MARKER")" = executed:fix/detect-accuracy-20261105 ] \
                || { echo "установка $tool идёт не с ветки main" >&2; exit 1; }
        fi
        # Сперва через проводник на VPS.
        [ "$(head -1 "$GATE_LOG")" = "http://85.192.60.175:9444" ] \
            || { echo "команда $tool $script не идёт сперва через VPS" >&2; exit 1; }
        # Проводник лёг — загрузка повторяется напрямую и исполняется.
        rm -f "$RUN_MARKER" "$GATE_LOG"
        GATE_FAIL=1 sh -c "$command" || { echo "отказ VPS сорвал команду $tool $script" >&2; exit 1; }
        if [ ! -s "$RUN_MARKER" ] || [ ! -s "$GATE_LOG" ]; then
            echo "после отказа VPS команда $tool $script не пошла напрямую" >&2; exit 1
        fi
        [ ! -e "$(cat "$CURL_TARGET")" ] || { echo "временный файл остался: $tool $script" >&2; exit 1; }
        rm -f "$GATE_LOG"
    done
echo 'README install/uninstall (curl): запуск через VPS и напрямую, защита от неполной загрузки и уборка прошли'
