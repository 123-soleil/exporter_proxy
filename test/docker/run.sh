#!/usr/bin/env bash
# Smoke test of the container image, run the way the README describes:
# hardened (read-only, no capability, no-new-privileges), uid 65532, host
# network, configuration directory mounted read-only. Checks serving, a
# reload with SIGHUP, and a clean stop.
#
#   test/docker/run.sh exporter_proxy:test
set -euo pipefail

IMAGE=${1:?usage: run.sh <image>}
NAME=exporter_proxy-test
WORK=$(mktemp -d)
CONF=$WORK/etc
DATA=$WORK/data

step() { printf '\n=== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	docker logs "$NAME" >&2 || true
	exit 1
}
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$1" || true; }
served() { [ "$(code "$1")" = 200 ]; }
wait_for() {
	local what=$1
	shift
	for _ in $(seq 50); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "timed out waiting for: $what"
}
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

step "Image"
docker run --rm "$IMAGE" --version
user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE")
[ "$user" = 65532:65532 ] || fail "image user $user, want 65532:65532"
echo "ok: runs as $user"

step "Configuration"
mkdir -p "$CONF" "$DATA"
printf '{}\n' >"$CONF/web.yml"
printf '# TYPE batch_last_run gauge\nbatch_last_run 1\n' >"$DATA/batch.prom"
write_config() { # $1: extra routes
	cat >"$CONF/config.yml" <<EOF
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/exporter_proxy/web.yml
listeners:
  - name: plain
    listen: "127.0.0.1:9100"
    web_config_file: /etc/exporter_proxy/web.yml
    routes:
      - path: /batch/metrics
        file: /data/batch.prom
        max_age: 15m
$1
EOF
}
write_config ""
chmod 0755 "$WORK" "$CONF" "$DATA"
chmod 0644 "$CONF"/* "$DATA"/*

step "--check"
docker run --rm -v "$CONF:/etc/exporter_proxy:ro" -v "$DATA:/data:ro" "$IMAGE" --check

step "Start (hardened)"
docker run -d --name "$NAME" --network host \
	-v "$CONF:/etc/exporter_proxy:ro" -v "$DATA:/data:ro" \
	--read-only --cap-drop ALL --security-opt no-new-privileges \
	--stop-timeout 30 "$IMAGE" >/dev/null
wait_for "metrics endpoint" served http://127.0.0.1:9999/metrics
served http://127.0.0.1:9100/batch/metrics || fail "file route not served"
curl -fsS http://127.0.0.1:9100/batch/metrics | grep -q '^batch_last_run 1' || fail "wrong content"
echo "ok: serving"

step "Reload with SIGHUP (directory mount sees the new file)"
write_config "      - path: /extra/metrics
        file: /data/batch.prom
        max_age: 15m"
# Atomic replacement, like an editor: a single-file mount would miss it.
cp "$CONF/config.yml" "$CONF/config.yml.new" && mv "$CONF/config.yml.new" "$CONF/config.yml"
chmod 0644 "$CONF/config.yml"
docker kill --signal HUP "$NAME" >/dev/null
wait_for "new route after reload" served http://127.0.0.1:9100/extra/metrics
echo "ok: reloaded"

step "Stop"
docker stop "$NAME" >/dev/null
exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$NAME")
[ "$exit_code" = 0 ] || fail "exit code $exit_code, want 0"
echo "ok: stopped cleanly"

step "All Docker checks passed"
