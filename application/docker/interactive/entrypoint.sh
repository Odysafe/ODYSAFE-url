#!/bin/sh
set -eu

: "${XPRA_PASSWORD:?XPRA_PASSWORD must be set for each session}"
mkdir -p /run/odysafe
chmod 700 /run/odysafe
rm -f /run/odysafe/finish
export XDG_RUNTIME_DIR=/run/odysafe

finish_capture() {
    touch /run/odysafe/finish
}
trap finish_capture USR1 TERM INT

xpra seamless :100 \
  --daemon=no --attach=no --html=on \
  --bind-tcp=0.0.0.0:14500,auth=env\(name=XPRA_PASSWORD\) \
  --socket-dirs=/run/odysafe --ssh-upgrade=no \
  --start-new-commands=no --system-tray=no --notifications=no \
  --file-transfer=no --open-files=no --open-url=no --printing=no \
  --clipboard=no --dbus=no --dbus-control=no --mdns=no --webcam=no \
  --audio=no --speaker=disabled --microphone=disabled \
  --exit-with-children=no --max-size=1920x1080 \
  --dpi=96 --encoding=rgb --auto-refresh-delay=0 --quality=100 --min-quality=95 &
xpra_pid=$!

ready=0
for _ in $(seq 1 100); do
    if [ -S /run/odysafe/xpra/100/socket ]; then
        ready=1
        break
    fi
    kill -0 "$xpra_pid" 2>/dev/null || break
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "Xpra did not become ready" >&2
    exit 1
fi

cleanup() {
    finish_capture
    kill "$xpra_pid" 2>/dev/null || true
    wait "$xpra_pid" 2>/dev/null || true
}
trap cleanup EXIT

export DISPLAY=:100 ODYSAFE_INTERACTIVE=1
python -m app.sandbox.runner &
capture_pid=$!
capture_status=0
while kill -0 "$capture_pid" 2>/dev/null; do
    set +e
    wait "$capture_pid"
    capture_status=$?
    set -e
done
exit "$capture_status"
