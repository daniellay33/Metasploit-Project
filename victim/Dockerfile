FROM linuxserver/webtop:ubuntu-xfce

RUN apt-get update && \
    apt-get install -y ffmpeg pulseaudio pulseaudio-utils scrot x11-utils xdotool xclip \
        firefox libavcodec-extra gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Write YouTube autostart before XFCE loads
COPY autostart.sh /etc/cont-init.d/98-autostart
RUN chmod +x /etc/cont-init.d/98-autostart
