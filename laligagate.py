#!/usr/bin/env python3
"""
Bypass LaLigaGate como servicio autonomo.

Consulta hayahora.futbol y, mientras haya bloqueos de IP por futbol en Espana,
pone los registros DNS configurados en modo "DNS only" (sin proxy de Cloudflare).
Cuando los bloqueos cesan y pasa el periodo de espera configurado, restaura el
proxy a los registros que estaban proxied antes del bypass.

Solo biblioteca estandar: pensado para correr en un LXC Debian sin dependencias.

Subcomandos:
  daemon              bucle continuo (lo arranca systemd)
  check [--dry-run]   una comprobacion y aplica la decision si procede
  status              estado guardado, sin llamar a la red
  proxy on|off|auto   intervencion manual
  test                comprueba credenciales y lista los registros DNS
"""

import argparse
import calendar
import email.utils
import fcntl
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.2.0"
CONFIG_PATH = os.environ.get("BLG_CONFIG", "/etc/laligagate/config.json")
STATE_DIR = os.environ.get("BLG_STATE_DIR", "/var/lib/laligagate")
STATE_PATH = os.path.join(STATE_DIR, "state.json")
LOCK_PATH = os.path.join(STATE_DIR, "lock")
USER_AGENT = "laligagate/%s (self-hosted)" % VERSION

CF_BASE = "https://api.cloudflare.com/client/v4"
PROXYABLE_TYPES = ("A", "AAAA", "CNAME")
ISP_FILES = (
    ("movistar", "Movistar"),
    ("vodafone", "Vodafone"),
    ("orange", "Orange"),
    ("masmovil", "Masmovil"),
    ("digi", "DIGI"),
)
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
OWN_IPS_TTL = 6 * 3600

# Regla de hayahora.futbol (la que decide su veredicto SÍ/NO). Modo "web".
WEB_DATA_FILE = "data.json"
WEB_MAX_BYTES = 64 * 1024 * 1024
WEB_CF_PAIR = ("188.114.96.5", "188.114.97.5")
WEB_MIN_IPS_OVER_2_ISPS = 10


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------

def now():
    return int(time.time())


def log(message):
    print("%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message), flush=True)


def human_duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return "%ds" % seconds
    minutes = seconds // 60
    if minutes < 60:
        return "%dm" % minutes
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return "%dh%02dm" % (hours, minutes)
    days, hours = divmod(hours, 24)
    return "%dd%02dh" % (days, hours)


def http(url, method="GET", headers=None, payload=None, timeout=20, retries=3, limit=None):
    """Peticion HTTP con reintentos. Devuelve (status, headers, body)."""
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    last_error = "sin detalle"
    for attempt in range(1, retries + 1):
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("User-Agent", USER_AGENT)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(limit + 1) if limit else response.read()
                if limit and len(body) > limit:
                    raise RuntimeError("respuesta mayor de %d bytes" % limit)
                return response.status, response.headers, body
        except urllib.error.HTTPError as exc:
            body = exc.read(limit + 1) if limit else exc.read()
            # Un 4xx no se arregla reintentando (salvo throttling).
            if exc.code < 500 and exc.code != 429:
                return exc.code, exc.headers, body
            last_error = "HTTP %d" % exc.code
        except Exception as exc:  # red, TLS, timeout
            last_error = str(exc) or exc.__class__.__name__
        if attempt < retries:
            time.sleep(2 * attempt)
    raise RuntimeError("%s %s: %s" % (method, url, last_error))


def parse_ipv4_set(text):
    """Lineas que sean IPv4 validas. Una pagina de error con HTTP 200 no cuenta."""
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ips.add(str(ipaddress.IPv4Address(line)))
        except ValueError:
            continue
    return ips


def fetch_ip_list(url, limit=1024 * 1024):
    """Devuelve (ips, last_modified_ts, error)."""
    try:
        status, headers, body = http(url, timeout=15, limit=limit)
    except RuntimeError as exc:
        return set(), 0, str(exc)
    if status != 200:
        return set(), 0, "HTTP %d" % status
    last_modified = headers.get("Last-Modified")
    timestamp = 0
    if last_modified:
        try:
            timestamp = int(email.utils.parsedate_to_datetime(last_modified).timestamp())
        except (TypeError, ValueError):
            timestamp = 0
    return parse_ipv4_set(body.decode("utf-8", "replace")), timestamp, ""


# --------------------------------------------------------------------------
# Cloudflare
# --------------------------------------------------------------------------

class CloudflareError(RuntimeError):
    pass


class Cloudflare:
    def __init__(self, token, zone_id):
        self.token = token
        self.zone_id = zone_id

    def _call(self, path, method="GET", payload=None):
        status, _, body = http(
            CF_BASE + path,
            method,
            headers={
                "Authorization": "Bearer %s" % self.token,
                "Content-Type": "application/json",
            },
            payload=payload,
            timeout=30,
        )
        try:
            data = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            data = {}
        if not 200 <= status < 300 or not data.get("success"):
            errors = "; ".join(
                str(item.get("message", "?")) for item in (data.get("errors") or [])
            )
            raise CloudflareError("%s %s: %s" % (method, path, errors or "HTTP %d" % status))
        return data

    def zone(self):
        return self._call("/zones/%s" % self.zone_id)["result"]

    def records(self):
        found = []
        page = 1
        while page <= 50:
            data = self._call(
                "/zones/%s/dns_records?per_page=100&page=%d" % (self.zone_id, page)
            )
            found.extend(data.get("result") or [])
            info = data.get("result_info") or {}
            per_page = int(info.get("per_page") or 100)
            total = int(info.get("total_count") or 0)
            if per_page <= 0 or page * per_page >= total:
                break
            page += 1
        return found

    def set_proxied(self, record, proxied):
        payload = {"proxied": bool(proxied)}
        # Cloudflare exige TTL automatico (1) cuando el registro esta proxied.
        if proxied and int(record.get("ttl") or 1) != 1:
            payload["ttl"] = 1
        result = self._call(
            "/zones/%s/dns_records/%s" % (self.zone_id, record["id"]),
            "PATCH",
            payload,
        )["result"]
        return bool(result.get("proxied"))


# --------------------------------------------------------------------------
# Deteccion
# --------------------------------------------------------------------------

def parse_web_last_update(value):
    if not value:
        return 0
    try:
        return calendar.timegm(time.strptime(str(value), "%Y-%m-%d %H:%M:%SZ"))
    except (TypeError, ValueError):
        return 0


def parse_web_status(payload):
    """Replica la regla del frontend de hayahora.futbol.

    Activo si mas de 10 IPs de Cloudflare estan bloqueadas simultaneamente por
    mas de 2 operadores, o si el par 188.114.96.5/188.114.97.5 esta bloqueado.
    """
    blocked = set()
    isp_hits = {}
    cf_hits = {}
    pair_blocked = set()
    for entry in payload.get("data") or []:
        changes = entry.get("stateChanges") or []
        if not changes:
            continue
        # La web usa stateChanges[-1], no el timestamp maximo.
        if changes[-1].get("state") is not True:
            continue
        ip = str(entry.get("ip") or "")
        if not ip:
            continue
        isp = str(entry.get("isp") or "?")
        blocked.add(ip)
        isp_hits[isp] = isp_hits.get(isp, 0) + 1
        if entry.get("description") == "Cloudflare":
            cf_hits[ip] = cf_hits.get(ip, 0) + 1
            if ip in WEB_CF_PAIR:
                pair_blocked.add(ip)
    over_two = sum(1 for hits in cf_hits.values() if hits > 2)
    pair_ok = all(ip in pair_blocked for ip in WEB_CF_PAIR)
    active = over_two > WEB_MIN_IPS_OVER_2_ISPS or pair_ok
    return active, blocked, isp_hits, over_two, pair_ok


def check_web_blocks(config, result, base):
    max_age_hours = float(config["source"].get("max_data_age_hours", 3))
    try:
        status, _, body = http(
            base + WEB_DATA_FILE, timeout=30, limit=WEB_MAX_BYTES, retries=2
        )
    except RuntimeError as exc:
        result["error"] = str(exc)
        result["source"] = "web (error)"
        return result
    if status != 200:
        result["error"] = "HTTP %d al leer %s" % (status, WEB_DATA_FILE)
        result["source"] = "web (error)"
        return result
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        result["error"] = "%s no es JSON valido: %s" % (WEB_DATA_FILE, exc)
        result["source"] = "web (error)"
        return result

    last_update = parse_web_last_update(payload.get("lastUpdate"))
    result["last_update"] = last_update
    if last_update and max_age_hours > 0:
        age = now() - last_update
        if age > max_age_hours * 3600:
            result["error"] = (
                "los datos de hayahora.futbol llevan %s sin actualizarse; "
                "no se puede saber si hay bloqueos" % human_duration(age)
            )
            result["source"] = "web (obsoleto)"
            return result

    active, blocked, isp_hits, over_two, pair_ok = parse_web_status(payload)
    result["blocked"] = active
    result["blocked_ips"] = len(blocked)
    result["blocked_isps"] = len(isp_hits)
    result["isp_names"] = [
        "%s(%d)" % (name, hits) for name, hits in sorted(isp_hits.items())
    ]
    result["source"] = "web(r=%d,par=%s)" % (over_two, "si" if pair_ok else "no")
    return result


def check_blocks(config, own_ips):
    settings = config["detection"]
    mode = settings.get("mode", "global")
    min_isps = max(1, int(settings.get("min_isps", 1)))
    base = config["source"]["txt_base"].rstrip("/") + "/"

    degraded = False
    if mode == "own_ip" and not own_ips:
        # Precision imposible: mejor falsa alarma que bloqueo perdido.
        mode = "global"
        degraded = True

    result = {
        "blocked": False,
        "error": "",
        "blocked_ips": 0,
        "blocked_isps": 0,
        "isp_names": [],
        "mode": mode,
        "source": "txt",
        "last_update": 0,
    }

    if mode == "web":
        return check_web_blocks(config, result, base)

    ips, last_update, error = fetch_ip_list(base + "blocked-any.txt")
    result["error"] = error
    result["last_update"] = last_update
    if error:
        return result

    max_age_hours = float(config["source"].get("max_data_age_hours", 3))
    if last_update and max_age_hours > 0:
        age = now() - last_update
        if age > max_age_hours * 3600:
            result["error"] = (
                "los datos de hayahora.futbol llevan %s sin actualizarse; "
                "no se puede saber si hay bloqueos" % human_duration(age)
            )
            result["source"] = "txt (obsoleto)"
            return result

    candidates = (ips & own_ips) if mode == "own_ip" else ips
    result["blocked_ips"] = len(candidates)

    if not candidates:
        result["source"] = "txt+sin-ips" if degraded else "txt"
        return result

    if min_isps <= 1 and mode == "global":
        result["blocked"] = True
        result["source"] = "txt+sin-ips" if degraded else "txt"
        return result

    names = []
    any_ok = False
    for slug, label in ISP_FILES:
        isp_ips, _, isp_error = fetch_ip_list(base + "blocked-%s.txt" % slug)
        if isp_error:
            continue
        any_ok = True
        hits = (candidates & isp_ips) if mode == "own_ip" else isp_ips
        if hits:
            names.append(label)

    if not any_ok:
        # Hay bloqueo en la union pero no se pudo desglosar: no nos la jugamos.
        result["blocked"] = True
        result["source"] = "txt (ISPs sin determinar)"
    else:
        result["isp_names"] = names
        result["blocked_isps"] = len(names)
        result["blocked"] = len(names) >= min_isps
        result["source"] = "txt"

    if degraded:
        result["source"] += "+sin-ips"
    return result


def resolve_via_doh(name):
    for endpoint in DOH_ENDPOINTS:
        url = "%s?name=%s&type=A" % (endpoint, urllib.parse.quote(name))
        try:
            status, _, body = http(
                url, headers={"Accept": "application/dns-json"}, timeout=10, retries=2
            )
            if status != 200:
                continue
            data = json.loads(body.decode("utf-8", "replace"))
            ips = set()
            for answer in data.get("Answer") or []:
                if answer.get("type") != 1:
                    continue
                try:
                    ips.add(str(ipaddress.IPv4Address(answer.get("data", ""))))
                except ValueError:
                    continue
            if ips:
                return ips
        except (RuntimeError, ValueError):
            continue
    try:
        return {info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)}
    except OSError:
        return set()


def own_ips_for(records, state):
    """IPs publicas (edge de Cloudflare) que resuelven los registros proxied."""
    cache = state.setdefault("own_ips", {"ts": 0, "by_name": {}})
    if cache.get("by_name") and now() - int(cache.get("ts", 0)) < OWN_IPS_TTL:
        return {ip for ips in cache["by_name"].values() for ip in ips}

    by_name = {}
    for record in records:
        if not record.get("proxied"):
            continue
        ips = resolve_via_doh(record["name"])
        if ips:
            by_name[record["name"]] = sorted(ips)
    if by_name:
        cache["ts"] = now()
        cache["by_name"] = by_name
    return {ip for ips in by_name.values() for ip in ips}


# --------------------------------------------------------------------------
# Configuracion y estado
# --------------------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except OSError as exc:
        raise SystemExit("No se puede leer %s: %s" % (CONFIG_PATH, exc))
    except ValueError as exc:
        raise SystemExit("%s no es JSON valido: %s" % (CONFIG_PATH, exc))

    cloudflare = config.get("cloudflare") or {}
    if not cloudflare.get("api_token"):
        raise SystemExit("Falta cloudflare.api_token en %s" % CONFIG_PATH)
    if not cloudflare.get("zone_id"):
        raise SystemExit("Falta cloudflare.zone_id en %s" % CONFIG_PATH)

    config.setdefault("detection", {})
    config.setdefault("timing", {})
    config.setdefault("source", {})
    config.setdefault("records", [])
    config.setdefault("hooks", {})
    config["detection"].setdefault("mode", "global")
    config["detection"].setdefault("min_isps", 1)
    config["timing"].setdefault("interval_minutes", 15)
    config["timing"].setdefault("restore_wait_minutes", 60)
    config["source"].setdefault("txt_base", "https://hayahora.futbol/estado/")
    config["source"].setdefault("max_data_age_hours", 3)
    config["hooks"].setdefault("timeout_seconds", 30)
    return config


def default_state():
    return {
        "blocked": None,
        "proxy_off": False,
        "proxy_since": 0,
        "originals": {},
        "manual": "auto",
        "cleared_at": 0,
        "last_check": 0,
        "last_error": "",
        "last_source": "",
        "last_mode": "",
        "last_isp_names": [],
        "blocked_ips": 0,
        "hook_state": None,
        "own_ips": {"ts": 0, "by_name": {}},
    }


def load_state():
    state = default_state()
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            state.update(stored)
    except (OSError, ValueError):
        pass
    if not isinstance(state.get("originals"), dict):
        state["originals"] = {}
    return state


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    temporary = STATE_PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False, sort_keys=True)
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE_PATH)


class Lock:
    """Evita que el demonio y un comando manual actuen a la vez."""

    def __init__(self):
        self.handle = None

    def __enter__(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.handle = open(LOCK_PATH, "w")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
        return self

    @property
    def acquired(self):
        return self.handle is not None

    def __exit__(self, *_):
        if self.handle:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()


# --------------------------------------------------------------------------
# Ciclo principal
# --------------------------------------------------------------------------

def select_targets(records, config):
    wanted = [str(name).strip().lower() for name in config["records"] if str(name).strip()]
    candidates = [
        record
        for record in records
        if str(record.get("type", "")).upper() in PROXYABLE_TYPES
    ]
    if not wanted:
        return candidates, []

    zone_name = str(config["cloudflare"].get("zone_name") or "").lower()
    normalized = []
    for name in wanted:
        normalized.append(zone_name if name == "@" and zone_name else name)
    targets = [record for record in candidates if str(record["name"]).lower() in normalized]
    found = {str(record["name"]).lower() for record in targets}
    missing = [name for name in normalized if name not in found]
    return targets, missing


def restore_originals(cloudflare, targets, state):
    """Reactiva el proxy solo en los registros que apagamos nosotros."""
    originals = state["originals"]
    restored = []
    for name in list(originals):
        match = next((record for record in targets if record["name"] == name), None)
        if match is None:
            log("AVISO: %s ya no existe; se descarta del estado" % name)
            originals.pop(name, None)
            continue
        if match.get("proxied") is False:
            cloudflare.set_proxied(match, True)
            restored.append(name)
        originals.pop(name, None)
    state["proxy_off"] = False
    state["proxy_since"] = 0
    state["cleared_at"] = 0
    return restored


def run_hooks(config, state, blocked, dry_run=False):
    """Ejecuta el hook de transicion una sola vez por cambio de estado.

    Los comandos son listas de argumentos (sin shell). Si fallan se deja
    hook_state sin actualizar para reintentar en el siguiente ciclo.
    """
    hooks = config.get("hooks") or {}
    if not hooks:
        return

    key = "on_blocked" if blocked else "on_clear"
    command = hooks.get(key) or []
    if isinstance(command, str):
        command = [command]
    command = [str(part) for part in command]

    if state.get("hook_state") is blocked:
        return
    if not command:
        if not dry_run:
            state["hook_state"] = blocked
        return

    tag = " [dry-run]" if dry_run else ""
    log("hook %s%s: %s" % (key, tag, " ".join(command)))
    if dry_run:
        return

    timeout = int(hooks.get("timeout_seconds", 30))
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # binario ausente, timeout, permisos...
        log("AVISO: hook %s no se pudo ejecutar: %s" % (key, exc))
        return

    output = (completed.stdout or "").strip()
    if output:
        log("hook %s: %s" % (key, output.replace("\n", " | ")[:300]))
    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "").strip()
        log(
            "AVISO: hook %s devolvio %d; se reintentara en el siguiente ciclo: %s"
            % (key, completed.returncode, error[:200])
        )
        return

    state["hook_state"] = blocked


def apply_cycle(config, state, dry_run=False):
    tag = " [dry-run]" if dry_run else ""
    cloudflare = Cloudflare(
        config["cloudflare"]["api_token"], config["cloudflare"]["zone_id"]
    )

    records = cloudflare.records()
    targets, missing = select_targets(records, config)
    if missing:
        log("AVISO: registros configurados que no existen en la zona: %s" % ", ".join(missing))
    if not targets:
        raise RuntimeError("no hay registros DNS que gestionar (revisa 'records' en la config)")

    own_ips = set()
    if config["detection"].get("mode") == "own_ip":
        own_ips = own_ips_for([r for r in targets if r.get("proxied")], state)

    status = check_blocks(config, own_ips)
    state["last_check"] = now()

    if status["error"]:
        state["last_error"] = status["error"]
        log("ERROR en la fuente: %s. Se mantiene el estado actual%s" % (status["error"], tag))
        if not dry_run:
            save_state(state)
        return

    state["blocked"] = status["blocked"]
    state["last_source"] = status["source"]
    state["last_mode"] = status["mode"]
    state["last_isp_names"] = status["isp_names"]
    state["blocked_ips"] = status["blocked_ips"]
    state["last_error"] = ""
    isps = ", ".join(status["isp_names"]) if status["isp_names"] else "sin determinar"
    log(
        "bloqueos: %s | IPs: %d | ISPs: %s | fuente: %s%s"
        % (
            "SI" if status["blocked"] else "no",
            status["blocked_ips"],
            isps,
            status["source"],
            tag,
        )
    )

    manual = state.get("manual", "auto")
    wait_seconds = int(config["timing"]["restore_wait_minutes"]) * 60
    desired = None

    if manual == "off":
        desired = False
        state["cleared_at"] = 0
    elif status["blocked"]:
        state["cleared_at"] = 0
        desired = False
    elif state.get("proxy_off"):
        cleared_at = int(state.get("cleared_at") or 0)
        if cleared_at <= 0:
            state["cleared_at"] = now()
            log(
                "sin bloqueos: proxy se restaurara en %d min%s"
                % (int(config["timing"]["restore_wait_minutes"]), tag)
            )
        elif now() - cleared_at >= wait_seconds:
            desired = True

    originals = state["originals"]

    if desired is False:
        for record in targets:
            name = record["name"]
            if record.get("proxied") is True:
                if not dry_run:
                    originals.setdefault(
                        name,
                        {
                            "id": record["id"],
                            "ttl": int(record.get("ttl") or 1),
                            "since": now(),
                        },
                    )
                    cloudflare.set_proxied(record, False)
                log("proxy OFF%s: %s" % (tag, name))
            elif name in originals and record.get("proxied") is not False:
                # Alguien lo volvio a proxificar durante el bypass: se deshace.
                if not dry_run:
                    cloudflare.set_proxied(record, False)
                log("proxy OFF%s (revertido): %s" % (tag, name))
        if not dry_run:
            state["proxy_off"] = bool(originals)
            if state["proxy_off"] and not state.get("proxy_since"):
                state["proxy_since"] = now()
            save_state(state)

    elif desired is True:
        if dry_run:
            log("proxy ON [dry-run]: %s" % ", ".join(sorted(originals)))
        else:
            restored = restore_originals(cloudflare, targets, state)
            log(
                "proxy restaurado: %s"
                % (", ".join(restored) if restored else "no habia nada que restaurar")
            )
            save_state(state)

    elif not dry_run:
        save_state(state)

    # Los hooks leen el estado ya persistido, asi que van despues del save.
    run_hooks(config, state, status["blocked"], dry_run=dry_run)
    if not dry_run:
        save_state(state)


def cmd_check(config, dry_run):
    with Lock() as lock:
        if not lock.acquired:
            log("otra ejecucion en curso; se omite esta comprobacion")
            return 0
        state = load_state()
        apply_cycle(config, state, dry_run=dry_run)
    return 0


def cmd_daemon(config):
    interval = max(1, int(config["timing"]["interval_minutes"])) * 60
    log(
        "servicio iniciado: intervalo %d min, espera %d min, modo %s"
        % (
            interval // 60,
            int(config["timing"]["restore_wait_minutes"]),
            config["detection"]["mode"],
        )
    )
    while True:
        try:
            with Lock() as lock:
                if not lock.acquired:
                    log("otra ejecucion en curso; se omite esta comprobacion")
                else:
                    apply_cycle(config, load_state())
        except Exception as exc:  # el demonio no muere por un fallo puntual
            log("ERROR en el ciclo: %s" % exc)
        time.sleep(interval)


def cmd_status(config):
    state = load_state()
    cloudflare = config["cloudflare"]
    print("Config:        %s" % CONFIG_PATH)
    print("Zona:          %s (%s)" % (cloudflare.get("zone_name") or "?", cloudflare["zone_id"]))
    print("Registros:     %s" % (", ".join(config["records"]) or "todos los proxied"))
    if config["detection"]["mode"] == "web":
        print(
            "Deteccion:     web (umbral de hayahora.futbol), cada %s min, espera %s min"
            % (
                config["timing"]["interval_minutes"],
                config["timing"]["restore_wait_minutes"],
            )
        )
    else:
        print(
            "Deteccion:     %s, ISPs minimos %s, cada %s min, espera %s min"
            % (
                config["detection"]["mode"],
                config["detection"]["min_isps"],
                config["timing"]["interval_minutes"],
                config["timing"]["restore_wait_minutes"],
            )
        )
    checked = int(state.get("last_check") or 0)
    print(
        "Ultima comprob.: %s"
        % (("%s (hace %s)" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(checked)), human_duration(now() - checked))) if checked else "nunca")
    )
    if state.get("blocked") is None:
        print("Bloqueos:      desconocido")
    else:
        isps = ", ".join(state.get("last_isp_names") or []) or "sin determinar"
        print(
            "Bloqueos:      %s (%d IPs; ISPs: %s; fuente %s)"
            % (
                "SI" if state["blocked"] else "no",
                int(state.get("blocked_ips") or 0),
                isps,
                state.get("last_source") or "?",
            )
        )
    if state.get("proxy_off"):
        since = int(state.get("proxy_since") or 0)
        print(
            "Proxy:         OFF desde %s"
            % ((time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since)) + " (hace %s)" % human_duration(now() - since)) if since else "hace un rato")
        )
        print("Registros OFF: %s" % ", ".join(sorted(state.get("originals") or {})))
    else:
        print("Proxy:         ON (sin cambios pendientes)")
    print("Manual:        %s" % ("OFF forzado por el usuario" if state.get("manual") == "off" else "automatico"))
    if state.get("last_error"):
        print("Ultimo error:  %s" % state["last_error"])
    if state.get("cleared_at"):
        print(
            "Restauracion:  en %s"
            % human_duration(int(state["cleared_at"]) + int(config["timing"]["restore_wait_minutes"]) * 60 - now())
        )


def cmd_test(config):
    cloudflare = Cloudflare(
        config["cloudflare"]["api_token"], config["cloudflare"]["zone_id"]
    )
    zone = cloudflare.zone()
    print("Credenciales: OK")
    print("Zona:         %s (%s)" % (zone.get("name"), zone.get("id")))
    targets, missing = select_targets(cloudflare.records(), config)
    if missing:
        print("AVISO: no existen: %s" % ", ".join(missing))
    print("Registros gestionados:")
    for record in targets:
        print(
            "  %-6s %-32s proxied=%-5s ttl=%-4s -> %s"
            % (
                record.get("type"),
                record.get("name"),
                record.get("proxied"),
                record.get("ttl"),
                record.get("content"),
            )
        )


def cmd_proxy(config, action):
    with Lock() as lock:
        if not lock.acquired:
            raise SystemExit("otra ejecucion en curso; reintenta en unos segundos")
        state = load_state()
        if action == "off":
            state["manual"] = "off"
            log("intervencion manual: proxy OFF hasta 'proxy on' o 'proxy auto'")
            save_state(state)
            apply_cycle(config, state)
            return

        if action == "on":
            state["manual"] = "auto"
            state["cleared_at"] = 0
            cloudflare = Cloudflare(
                config["cloudflare"]["api_token"], config["cloudflare"]["zone_id"]
            )
            targets, _ = select_targets(cloudflare.records(), config)
            if not targets:
                raise RuntimeError("no hay registros DNS que gestionar")
            restored = restore_originals(cloudflare, targets, state)
            save_state(state)
            log(
                "proxy restaurado manualmente: %s"
                % (", ".join(restored) if restored else "no habia nada que restaurar")
            )
            return

        state["manual"] = "auto"
        save_state(state)
        log("intervencion manual retirada; vuelve el automatismo")
        apply_cycle(config, state)


def main():
    parser = argparse.ArgumentParser(description="Bypass LaLigaGate (servicio autonomo)")
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("daemon", help="bucle continuo")
    check_parser = subparsers.add_parser("check", help="una comprobacion")
    check_parser.add_argument("--dry-run", action="store_true", help="no toca Cloudflare")
    subparsers.add_parser("status", help="estado guardado")
    subparsers.add_parser("test", help="credenciales y registros")
    proxy_parser = subparsers.add_parser("proxy", help="intervencion manual")
    proxy_parser.add_argument("action", choices=("on", "off", "auto"))

    args = parser.parse_args()
    config = load_config()

    if args.command == "daemon":
        cmd_daemon(config)
    elif args.command == "check":
        return cmd_check(config, args.dry_run)
    elif args.command == "status":
        cmd_status(config)
    elif args.command == "test":
        cmd_test(config)
    elif args.command == "proxy":
        cmd_proxy(config, args.action)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except (CloudflareError, RuntimeError) as exc:
        log("ERROR: %s" % exc)
        sys.exit(1)
