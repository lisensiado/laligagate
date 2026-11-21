#!/bin/sh
# Instala el servicio en un Debian/Ubuntu con systemd. Ejecutar como root.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Ejecuta este script como root." >&2
    exit 1
fi

here=$(dirname "$(readlink -f "$0")")

install -Dm755 "$here/laligagate.py" /opt/laligagate/laligagate.py
install -Dm644 "$here/laligagate.service" /etc/systemd/system/laligagate.service
ln -sf /opt/laligagate/laligagate.py /usr/bin/laligagate
systemctl daemon-reload

if [ ! -f /etc/laligagate/config.json ]; then
    install -Dm600 "$here/config.example.json" /etc/laligagate/config.json
    echo
    echo "Configura /etc/laligagate/config.json y comprueba con:"
    echo "  laligagate test"
    echo "  laligagate check --dry-run"
    echo "Despues arranca el servicio con:"
    echo "  systemctl enable --now laligagate"
    exit 0
fi

laligagate test
systemctl enable --now laligagate
echo "Servicio activo. Estado: laligagate status"
