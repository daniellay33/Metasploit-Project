#!/bin/bash

# Create XDG_RUNTIME_DIR for user abc — required for PulseAudio socket
mkdir -p /run/user/1000
chown -R abc:abc /run/user/1000
chmod 700 /run/user/1000

setsid bash -c '
    # Wait for Xvfb
    while [ ! -S /tmp/.X11-unix/X1 ]; do sleep 1; done
    sleep 2

    # Create /defaults/pid to unblock Selkies startup
    XVFB_PID=$(pgrep Xvfb | head -1)
    echo "${XVFB_PID:-1}" > /defaults/pid

    # Start PulseAudio with output sink
    sleep 2
    su -s /bin/bash abc -c "
        export HOME=/config
        export XDG_RUNTIME_DIR=/run/user/1000
        export PULSE_RUNTIME_PATH=/run/user/1000/pulse
        pulseaudio --start --exit-idle-time=-1 2>/tmp/pulse-start.log
        sleep 1
        pactl load-module module-null-sink sink_name=output sink_properties=device.description=output 2>/dev/null
        pactl set-default-sink output 2>/dev/null
    "
' &>/tmp/autostart.log &

exit 0
