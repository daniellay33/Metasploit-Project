#!/bin/bash
# Wait for X display to be ready, then open YouTube in Chromium
(
    for i in $(seq 1 30); do
        if DISPLAY=:1 xdpyinfo >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    su -s /bin/bash abc -c "DISPLAY=:1 chromium-browser --no-sandbox --disable-gpu --disable-dev-shm-usage 'https://www.youtube.com' &"
) &
