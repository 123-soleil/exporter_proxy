#!/usr/bin/env bash
# Integration test under a real systemd: installs exporter_proxy as the
# README describes (sysusers, the hardened unit of deploy/), with a
# socket-activated TLS + basic auth listener on port 443, then checks
# serving, authentication, reload (good and bad), privileges and stop.
#
# Run as root on a disposable machine with systemd as PID 1 (the GitHub
# Actions Ubuntu runner): it installs files under /usr and /etc.
#
#   sudo test/systemd/run.sh bin/exporter_proxy
set -euo pipefail

BIN=${1:?usage: run.sh <path to the exporter_proxy binary>}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
CONF=/etc/exporter_proxy
DATA=/var/lib/exporter_proxy-test
USER_NAME=prometheus
USER_PASS=integration-test-password

step() { printf '\n=== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	journalctl -u exporter_proxy --no-pager -n 100 >&2 || true
	exit 1
}

# code URL [curl options...]: HTTP status of a request.
code() {
	local url=$1
	shift
	curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$@" "$url" || true
}

# expect_code WANT URL [curl options...]
expect_code() {
	local want=$1 url=$2 got
	shift 2
	got=$(code "$url" "$@")
	[ "$got" = "$want" ] || fail "$url: code $got, want $want"
	echo "ok: $url -> $got"
}

# metric NAME_AND_LABELS: value of a sample of the metrics endpoint.
metric() {
	curl -fsS --max-time 5 http://127.0.0.1:9999/metrics | awk -v m="$1" '$1 == m { print $2 }'
}

# wait_for DESCRIPTION COMMAND...: retries COMMAND for up to 10 s.
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

reload_ok() { [ "$(metric exporter_proxy_config_last_reload_successful)" = "$1" ]; }
served() { [ "$(code "$1")" = 200 ]; }

step "Install (README, Installation)"
install -m 0755 "$BIN" /usr/sbin/exporter_proxy
install -m 0644 "$REPO/deploy/sysusers/exporter_proxy.conf.exemple" /usr/lib/sysusers.d/exporter_proxy.conf
systemd-sysusers
id exporter_proxy
install -m 0644 "$REPO/deploy/systemd/exporter_proxy.service.exemple" /usr/lib/systemd/system/exporter_proxy.service
install -m 0644 "$REPO/deploy/default/exporter_proxy.exemple" /etc/default/exporter_proxy
install -d -m 0755 "$CONF" "$CONF/tls"

step "Test material: TLS certificate, password, sources"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
	-subj /CN=exporter_proxy-test -addext subjectAltName=IP:127.0.0.1 \
	-keyout "$WORK/server.key" -out "$WORK/server.crt" 2>/dev/null
install -m 0644 "$WORK/server.crt" "$CONF/tls/server.crt"
install -m 0640 -g exporter_proxy "$WORK/server.key" "$CONF/tls/server.key"
hash=$(htpasswd -nbBC 10 "$USER_NAME" "$USER_PASS" | cut -d: -f2)

cat >"$WORK/web-basic.yml" <<EOF
tls_server_config:
  cert_file: $CONF/tls/server.crt
  key_file: $CONF/tls/server.key
basic_auth_users:
  $USER_NAME: $hash
EOF
install -m 0640 -g exporter_proxy "$WORK/web-basic.yml" "$CONF/web-basic.yml"
printf '{}\n' >"$WORK/web-plain.yml"
install -m 0640 -g exporter_proxy "$WORK/web-plain.yml" "$CONF/web-plain.yml"

# An HTTP upstream on 127.0.0.1 and a metrics file.
mkdir -p "$WORK/upstream" "$DATA"
printf '# TYPE upstream_up gauge\nupstream_up 1\n' >"$WORK/upstream/metrics"
python3 -m http.server 19100 --bind 127.0.0.1 --directory "$WORK/upstream" >/dev/null 2>&1 &
UPSTREAM_PID=$!
trap 'kill $UPSTREAM_PID 2>/dev/null || true; systemctl stop exporter_proxy exporter_proxy-node.socket 2>/dev/null || true' EXIT
printf '# TYPE batch_last_run gauge\nbatch_last_run 1\n' >"$DATA/batch.prom"
chmod 0644 "$DATA/batch.prom"
wait_for "upstream" curl -fsS http://127.0.0.1:19100/metrics

write_config() { # $1: extra routes for the plain listener
	cat >"$WORK/config.yml" <<EOF
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: $CONF/web-plain.yml
listeners:
  - name: node
    listen: "systemd:node"
    web_config_file: $CONF/web-basic.yml
    routes:
      - path: /node/metrics
        upstream: http://127.0.0.1:19100/metrics
  - name: plain
    listen: "127.0.0.1:9100"
    web_config_file: $CONF/web-plain.yml
    routes:
      - path: /batch/metrics
        file: $DATA/batch.prom
        max_age: 15m
$1
EOF
	install -m 0640 -g exporter_proxy "$WORK/config.yml" "$CONF/config.yml"
}
write_config ""

step "Socket activation (README, systemd socket activation): port 443"
cat >/etc/systemd/system/exporter_proxy-node.socket <<EOF
[Socket]
ListenStream=127.0.0.1:443
FileDescriptorName=node
Service=exporter_proxy.service
EOF
install -d /etc/systemd/system/exporter_proxy.service.d
cat >/etc/systemd/system/exporter_proxy.service.d/socket.conf <<EOF
[Unit]
Requires=exporter_proxy-node.socket
After=exporter_proxy-node.socket

[Service]
Sockets=exporter_proxy-node.socket
EOF
systemctl daemon-reload

step "--check as the service user"
# Self-signed certificate: no CA warning expected, only a clean check.
runuser -u exporter_proxy -- /usr/sbin/exporter_proxy --check --config "$CONF/config.yml"

step "Start"
systemctl start exporter_proxy-node.socket exporter_proxy
wait_for "service active" systemctl is-active --quiet exporter_proxy
wait_for "metrics endpoint" curl -fsS http://127.0.0.1:9999/metrics
pid=$(systemctl show -p MainPID --value exporter_proxy)
echo "MainPID $pid"

step "Hardening: unprivileged user, no capability"
[ "$(ps -o user= -p "$pid")" = exporter_proxy ] || fail "service not running as exporter_proxy"
capeff=$(awk '/^CapEff:/ { print $2 }' "/proc/$pid/status")
[ "$capeff" = 0000000000000000 ] || fail "effective capabilities $capeff, want none"
echo "ok: user exporter_proxy, CapEff $capeff (port 443 from systemd)"
systemd-analyze security exporter_proxy --no-pager | tail -1

step "Serving"
CURL_TLS=(--cacert "$CONF/tls/server.crt")
expect_code 200 https://127.0.0.1/node/metrics "${CURL_TLS[@]}" -u "$USER_NAME:$USER_PASS"
curl -fsS "${CURL_TLS[@]}" -u "$USER_NAME:$USER_PASS" https://127.0.0.1/node/metrics | grep -q '^upstream_up 1' ||
	fail "upstream metrics not served"
expect_code 401 https://127.0.0.1/node/metrics "${CURL_TLS[@]}"
expect_code 401 https://127.0.0.1/node/metrics "${CURL_TLS[@]}" -u "$USER_NAME:wrong-password"
expect_code 200 http://127.0.0.1:9100/batch/metrics
curl -fsS http://127.0.0.1:9100/batch/metrics | grep -q '^batch_last_run 1' || fail "file metrics not served"
expect_code 404 http://127.0.0.1:9100/missing/metrics
[ "$(metric 'exporter_proxy_auth_failures_total{listener="node",reason="invalid_credentials"}')" = 1 ] ||
	fail "invalid credentials not counted"

step "Reload: new route, same process"
write_config "      - path: /extra/metrics
        file: $DATA/batch.prom
        max_age: 15m"
systemctl reload exporter_proxy
wait_for "new route served" served http://127.0.0.1:9100/extra/metrics
reload_ok 1 || fail "reload not reported as successful"
[ "$(systemctl show -p MainPID --value exporter_proxy)" = "$pid" ] || fail "reload restarted the process"
echo "ok: /extra/metrics served after reload, MainPID unchanged"

step "Failed reload keeps the running configuration"
printf 'listeners: [\n' >"$WORK/broken.yml"
install -m 0640 -g exporter_proxy "$WORK/broken.yml" "$CONF/config.yml"
systemctl reload exporter_proxy
wait_for "failed reload reported" reload_ok 0
systemctl is-active --quiet exporter_proxy || fail "service stopped by a failed reload"
expect_code 200 http://127.0.0.1:9100/extra/metrics
expect_code 200 https://127.0.0.1/node/metrics "${CURL_TLS[@]}" -u "$USER_NAME:$USER_PASS"
write_config ""
systemctl reload exporter_proxy
wait_for "reload successful again" reload_ok 1

step "Stop"
systemctl stop exporter_proxy
result=$(systemctl show -p Result --value exporter_proxy)
status=$(systemctl show -p ExecMainStatus --value exporter_proxy)
[ "$result" = success ] && [ "$status" = 0 ] || fail "stop: Result=$result ExecMainStatus=$status"
echo "ok: stopped cleanly (Result=$result, exit $status)"

step "All systemd integration checks passed"
