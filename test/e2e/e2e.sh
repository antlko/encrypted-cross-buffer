#!/usr/bin/env bash
# End-to-end CLI test: real relay + 3 real `ecb` devices with FILE-BACKED fake
# clipboards. Everything lives in a temp dir; the real clipboard, keychain and
# config are never touched (ECB_CONFIG_DIR, ECB_KEYSTORE=file with the keychain
# disabled, ECB_CLIPBOARD_BACKEND=file:<dir>, HOME redirected).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ecb-e2e.XXXXXX")"
PIDS=()
cleanup() {
	local rc=$?
	for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
	sleep 0.3
	for p in ${PIDS[@]+"${PIDS[@]}"}; do kill -9 "$p" 2>/dev/null || true; done
	if [ $rc -ne 0 ]; then
		echo "--- e2e FAILED (rc=$rc); logs ---" >&2
		for f in "$TMP"/*.log; do [ -f "$f" ] && { echo "## $f" >&2; tail -n 25 "$f" >&2; }; done
	fi
	case "$TMP" in "${TMPDIR:-/tmp}"/ecb-e2e.*) rm -rf -- "$TMP" ;; esac
	exit $rc
}
trap cleanup EXIT INT TERM

fail() { echo "E2E FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }

# wait_for SECONDS COMMAND... : poll every 0.1 s until COMMAND succeeds.
wait_for() {
	local limit="$1"; shift
	local i=0 max=$((limit * 10))
	while [ $i -lt $max ]; do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

step "build"
mkdir -p bin
CGO_ENABLED=0 go build -o bin/ecb-relay ./cmd/ecb-relay
CGO_ENABLED=0 go build -o bin/ecb ./cmd/ecb
ECB="$ROOT/bin/ecb"

PORT="$(python3 -S -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
TOKEN="$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
URL="http://127.0.0.1:$PORT"
export HOME="$TMP/home"; mkdir -p "$HOME"
unset ECB_CONFIG_DIR ECB_CLIPBOARD_BACKEND

step "start relay on $URL"
ECB_ADDR="127.0.0.1:$PORT" ECB_DATA_DIR="$TMP/relay-data" ECB_ENROLL_TOKEN="$TOKEN" \
	"$ROOT/bin/ecb-relay" >"$TMP/relay.log" 2>&1 &
PIDS+=($!)
wait_for 10 curl -s -o /dev/null "$URL/v1/auth/challenge" -X POST -d '{}' || fail "relay did not start"

# dev N: run ecb as device N (isolated config, keystore file, fake clipboard).
dev() {
	local n="$1"; shift
	ECB_CONFIG_DIR="$TMP/d$n/cfg" ECB_KEYSTORE=file ECB_CLIPBOARD_BACKEND="file:$TMP/d$n/clip" \
		"$ECB" "$@"
}
for n in 1 2 3; do mkdir -p "$TMP/d$n/clip"; done

step "init device 1"
ECB_ENROLL_TOKEN="$TOKEN" dev 1 init --relay "$URL" --name dev1 >"$TMP/init1.log" 2>&1 || { cat "$TMP/init1.log" >&2; fail "init"; }

pair_device() { # N : pair device N into the group using device 1
	local n="$1"
	dev 1 pair >"$TMP/pair$n.out" 2>"$TMP/pair$n.log" &
	local ppid=$!
	PIDS+=($ppid)
	wait_for 10 grep -q '^Pairing code: ' "$TMP/pair$n.out" || fail "no pairing code for device $n"
	local code
	code="$(sed -n 's/^Pairing code: //p' "$TMP/pair$n.out" | head -n1)"
	[ -n "$code" ] || fail "empty pairing code"
	dev "$n" join --relay "$URL" --name "dev$n" "$code" >"$TMP/join$n.log" 2>&1 || { cat "$TMP/join$n.log" >&2; fail "join $n"; }
	wait "$ppid" || fail "pair for device $n failed: $(cat "$TMP/pair$n.log")"
}

step "pair devices 2 and 3"
pair_device 2
pair_device 3
dev 1 devices >"$TMP/devices.out" 2>&1; grep -q dev3 "$TMP/devices.out" || fail "dev3 not in roster"

step "wrong code is rejected"
dev 1 pair >"$TMP/pairx.out" 2>"$TMP/pairx.log" &
XPID=$!
PIDS+=($XPID)
wait_for 10 grep -q '^Pairing code: ' "$TMP/pairx.out" || fail "no pairing code (wrong-code test)"
XCODE="$(sed -n 's/^Pairing code: //p' "$TMP/pairx.out" | head -n1)"
mkdir -p "$TMP/d4/clip"
if ECB_CONFIG_DIR="$TMP/d4/cfg" ECB_KEYSTORE=file "$ECB" join --relay "$URL" --name dev4 "${XCODE%%-*}-wrong-wrong-wrong" >"$TMP/join4.log" 2>&1; then
	fail "join with a wrong code succeeded"
fi
if wait "$XPID"; then fail "pair succeeded despite a wrong code"; fi
dev 1 devices >"$TMP/devices2.out" 2>&1
[ "$(grep -c '^dev' "$TMP/devices2.out")" = "3" ] || fail "roster changed after a failed pairing"

step "run 3 daemons"
for n in 1 2 3; do
	dev "$n" run >"$TMP/run$n.log" 2>&1 &
	PIDS+=($!)
	eval "RUNPID$n=$!"
done
for n in 1 2 3; do
	wait_for 10 grep -q 'connected to the relay' "$TMP/run$n.log" || fail "daemon $n did not connect"
done

step "10k-line text: device 1 -> devices 2, 3 within 3 s"
seq 1 10000 | sed 's/^/clipboard line number /' >"$TMP/payload.txt"
mtime() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1"; }
cp "$TMP/payload.txt" "$TMP/d1/clip/.stage" && mv "$TMP/d1/clip/.stage" "$TMP/d1/clip/text"
M1="$(mtime "$TMP/d1/clip/text")"
same() { cmp -s "$TMP/payload.txt" "$TMP/d$1/clip/text"; }
wait_for 3 same 2 || fail "device 2 did not receive the text within 3 s"
wait_for 3 same 3 || fail "device 3 did not receive the text within 3 s"
echo "   delivered byte-identical to devices 2 and 3"

step "no echo loop"
sleep 2.5
same 1 || fail "device 1 clipboard changed"
[ "$(mtime "$TMP/d1/clip/text")" = "$M1" ] || fail "device 1 clipboard was rewritten"
SENT1="$(grep -c 'clipboard sent' "$TMP/run1.log" || true)"
SENT2="$(grep -c 'clipboard sent' "$TMP/run2.log" || true)"
SENT3="$(grep -c 'clipboard sent' "$TMP/run3.log" || true)"
APPL1="$(grep -c 'clipboard updated from another device' "$TMP/run1.log" || true)"
[ "$SENT1" = "1" ] && [ "$SENT2" = "0" ] && [ "$SENT3" = "0" ] && [ "$APPL1" = "0" ] ||
	fail "echo detected: sent=$SENT1/$SENT2/$SENT3 applied-on-1=$APPL1"
echo "   items sent: dev1=$SENT1 dev2=$SENT2 dev3=$SENT3 (expected 1/0/0)"
if grep -q 'clipboard line number' "$TMP"/run*.log; then fail "clipboard content found in logs"; fi

step "revoke device 3"
dev 1 devices rm dev3 >"$TMP/rm.log" 2>&1 || { cat "$TMP/rm.log" >&2; fail "devices rm"; }
printf 'second copy after revoke\n' >"$TMP/second.txt"
cp "$TMP/second.txt" "$TMP/d1/clip/.stage" && mv "$TMP/d1/clip/.stage" "$TMP/d1/clip/text"
wait_for 3 cmp -s "$TMP/second.txt" "$TMP/d2/clip/text" || fail "device 2 did not receive the second copy"
if cmp -s "$TMP/second.txt" "$TMP/d3/clip/text"; then fail "revoked device 3 received the item"; fi
wait_for 5 grep -q 'removed from the group' "$TMP/run3.log" || fail "device 3 did not report revocation"
wait_for 5 bash -c "! kill -0 $RUNPID3 2>/dev/null" || fail "device 3 daemon is still running"
set +e
wait "$RUNPID3"
RC3=$?
set -e
[ "$RC3" -ne 0 ] || fail "device 3 daemon exited 0 after revocation"
echo "   device 3 exited (rc=$RC3): $(grep -m1 'removed from the group' "$TMP/run3.log" | cut -c1-140)"

step "ecb help / status sanity"
"$ECB" help >"$TMP/help.out" 2>&1; grep -q 'Quick start' "$TMP/help.out" || fail "help"
dev 2 status >"$TMP/status.out" 2>&1 || fail "status failed"
grep -q 'reachable, this device is authenticated' "$TMP/status.out" || { cat "$TMP/status.out" >&2; fail "status output"; }

echo "E2E PASSED"
