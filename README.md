# laligagate

Servicio autonomo (sin WordPress, sin dependencias) que desactiva el proxy de
Cloudflare mientras hay bloqueos de IP por futbol en Espana y lo restaura
cuando terminan.

Consulta [hayahora.futbol](https://hayahora.futbol/) cada N minutos. Si hay
bloqueos activos, pone los registros DNS indicados en **DNS Only** (sin nube
naranja). Cuando cesan y pasa el periodo de espera, reactiva el proxy **solo en
los registros que apago el**, con su TTL original; nunca activa un registro que
ya era DNS Only.

## Como funciona

```
hayahora.futbol/estado/blocked-any.txt
        |
        v
datos frescos? --NO--> no se toca nada (error registrado)
        |
       SI
        v
bloqueos >= min_isps operadores? --NO--> si el proxy estaba OFF, empieza la espera
        |
       SI
        v
registros a DNS Only  ---->  pasan los bloqueos + espera  ---->  proxy restaurado
```

- **Datos obsoletos**: si la fuente lleva mas de `max_data_age_hours` sin
  actualizarse, se trata como error y no se cambia nada. Un fichero vacio de un
  generador parado no es un "no hay bloqueos".
- **Dos modos**: `global` (cualquier bloqueo en Espana, preventivo) y `own_ip`
  (solo si las IPs de Cloudflare que sirven estos registros aparecen en la
  lista, resueltas por DNS sobre HTTPS).
- **min_isps**: numero de operadores distintos con bloqueo para actuar (1-5).
- **Override manual**: `proxy off` congela el automatismo; `proxy on` restaura
  al instante; `proxy auto` devuelve el control al servicio.
- **Concurrencia**: un `flock` impide que el demonio y un comando manual hagan
  cambios opuestos a la vez.

## Requisitos

- Linux con systemd y Python 3.8 o superior (solo biblioteca estandar).
- Token de API de Cloudflare con `Zona > DNS > Editar` y `Zona > Zona > Leer`
  (plantilla "Editar zona DNS"), limitado a la zona.
- El `zone_id` de Cloudflare (panel de la zona, seccion API).

## Instalacion

```bash
git clone <este-repo> laligagate
cd laligagate
sudo ./install.sh
sudo editor /etc/laligagate/config.json   # token, zone_id, registros
sudo laligagate test
sudo laligagate check --dry-run           # muestra la decision sin tocar DNS
sudo systemctl enable --now laligagate
```

El script instala en `/opt/laligagate`, `/etc/laligagate` y la unidad systemd.
Si el fichero de configuracion ya existe, no lo sobrescribe.

## Configuracion (`/etc/laligagate/config.json`)

| Clave | Significado |
|---|---|
| `cloudflare.api_token` | Token con permiso de edicion DNS en la zona |
| `cloudflare.zone_id` | ID de la zona |
| `cloudflare.zone_name` | Nombre de la zona (para `"@"`) |
| `records` | Nombres a gestionar; `[]` = todos los A/AAAA/CNAME |
| `detection.mode` | `global` o `own_ip` |
| `detection.min_isps` | Operadores con bloqueo necesarios (1-5) |
| `timing.interval_minutes` | Frecuencia de comprobacion |
| `timing.restore_wait_minutes` | Espera antes de reactivar el proxy |
| `source.max_data_age_hours` | Antiguedad maxima aceptada de la fuente |

Tras editar la configuracion: `systemctl restart laligagate`.

## Comandos

```bash
laligagate status            # estado guardado, sin llamadas de red
laligagate check --dry-run   # que haria ahora, sin tocar Cloudflare
laligagate test              # credenciales, zona y registros gestionados
laligagate proxy off         # fuerza DNS Only y congela el automatismo
laligagate proxy on          # restaura el proxy ya
laligagate proxy auto        # vuelve al automatismo
journalctl -u laligagate -f
```

## Ficheros

- `/opt/laligagate/laligagate.py` - servicio
- `/etc/laligagate/config.json` - configuracion (0600)
- `/var/lib/laligagate/state.json` - estado y registros apagados
- `/etc/systemd/system/laligagate.service`

## Tests

Simulacion de la maquina de estados con Cloudflare y la fuente simuladas:

```bash
python3 tests/test_state_machine.py
```

## Aviso

Mientras el proxy esta en DNS Only el dominio resuelve a la IP de origen y esa
resolucion queda registrada en servicios de DNS pasivo. Es el precio de saltarse
el bloqueo: conviene proteger el origen con cortafuegos (por ejemplo, admitir
solo rangos de Cloudflare cuando el proxy vuelva).

Ademas, con un registro proxied Cloudflare fuerza TTL automatico (300 s), asi
que en cada transicion puede haber hasta ~5 minutos en que los resolutores
sirvan la IP anterior.

## Desinstalar

```bash
systemctl disable --now laligagate
laligagate proxy on    # si el proxy quedo en DNS Only
rm -rf /opt/laligagate /etc/laligagate /var/lib/laligagate /usr/bin/laligagate
rm /etc/systemd/system/laligagate.service
systemctl daemon-reload
```

## Licencia

GPLv3 (ver `LICENSE`). La logica de deteccion y conmutacion esta inspirada en
el plugin de WordPress [bypass-laligagate](https://github.com/fernandotellado/bypass-laligagate)
de Fernando Tellado (GPLv2+), reescrita como servicio autonomo.
