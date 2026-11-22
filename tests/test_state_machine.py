import importlib.util, json, os, shutil, sys, tempfile, time

STATE_DIR = tempfile.mkdtemp(prefix="blg-test-")
os.environ["BLG_STATE_DIR"] = STATE_DIR
os.environ["BLG_CONFIG"] = "/nonexistent"
spec = importlib.util.spec_from_file_location("blg", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "laligagate.py"))
blg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blg)

CONFIG = {
    "cloudflare": {"api_token": "x", "zone_id": "z", "zone_name": "example.com"},
    "records": ["*.example.com"],
    "detection": {"mode": "global", "min_isps": 1},
    "timing": {"interval_minutes": 15, "restore_wait_minutes": 60},
    "source": {"txt_base": "https://example.invalid/", "max_data_age_hours": 3},
}

RECORDS = [
    {"id": "1", "name": "*.example.com", "type": "A", "content": "1.2.3.4", "proxied": True, "ttl": 1},
    {"id": "2", "name": "static.example.com", "type": "A", "content": "1.2.3.4", "proxied": False, "ttl": 300},
]

class FakeCF:
    def __init__(self, records): self.data = records
    def records(self): return [dict(r) for r in self.data]
    def set_proxied(self, record, proxied):
        for r in self.data:
            if r["id"] == record["id"]:
                r["proxied"] = bool(proxied)
        return bool(proxied)

blg.Cloudflare = lambda token, zone: FakeCF(RECORDS)
CLOCK = [1_800_000_000]
blg.now = lambda: CLOCK[0]

REAL_CHECK_BLOCKS = blg.check_blocks

SOURCE = {"blocked": False, "error": "", "blocked_ips": 0, "blocked_isps": 0,
          "isp_names": [], "mode": "global", "source": "txt", "last_update": 0}
blg.check_blocks = lambda cfg, own_ips: dict(SOURCE)

def cycle(state):
    blg.apply_cycle(CONFIG, state)

def expect(cond, label):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        sys.exit(1)

state = blg.load_state()

# 1. Bloqueo -> solo el registro proxied se apaga y se recuerda.
SOURCE.update(blocked=True, blocked_ips=10)
cycle(state)
expect(RECORDS[0]["proxied"] is False, "bloqueo apaga el wildcard")
expect(RECORDS[1]["proxied"] is False, "no toca el registro que ya era DNS-only")
expect(list(state["originals"]) == ["*.example.com"], "guarda el estado original")
expect(blg.load_state()["proxy_off"] is True, "estado persistido")

# 2. Sigue el bloqueo: idempotente, sin duplicar.
cycle(state)
expect(list(state["originals"]) == ["*.example.com"], "idempotente con bloqueo activo")

# 3. Termina el bloqueo: no restaura hasta cumplir la espera.
SOURCE.update(blocked=False, blocked_ips=0)
cycle(state)
expect(RECORDS[0]["proxied"] is False, "espera antes de restaurar")
expect(state["cleared_at"] == CLOCK[0], "marca el fin de bloqueos")

# 4. Pasa la espera: restaura solo lo que apago.
CLOCK[0] += 59 * 60
cycle(state)
expect(RECORDS[0]["proxied"] is False, "59 min no basta")
CLOCK[0] += 2 * 60
cycle(state)
expect(RECORDS[0]["proxied"] is True, "restaura el proxy tras la espera")
expect(RECORDS[1]["proxied"] is False, "no activa registros que nunca estuvieron proxied")
expect(state["originals"] == {} and state["proxy_off"] is False, "limpia el estado")

# 5. Error de fuente: no cambia nada, deja el motivo.
SOURCE.update(blocked=True)
cycle(state)  # apaga otra vez
before = RECORDS[0]["proxied"]
SOURCE.update(error="datos obsoletos")
blg.check_blocks = lambda cfg, own: {"blocked": False, "error": "datos obsoletos", "blocked_ips": 0,
                                     "blocked_isps": 0, "isp_names": [], "mode": "global",
                                     "source": "txt (obsoleto)", "last_update": 0}
cycle(state)
expect(RECORDS[0]["proxied"] is before, "un error no toca el proxy")
expect("obsoletos" in state["last_error"], "registra el error")
blg.check_blocks = lambda cfg, own_ips: dict(SOURCE)
SOURCE.update(error="", blocked=True)
state["last_error"] = ""

# 6. Intervencion manual: off y restauracion inmediata con on.
blg.cmd_proxy(CONFIG, "off")
expect(blg.load_state()["manual"] == "off" and RECORDS[0]["proxied"] is False, "proxy off manual")
blg.cmd_proxy(CONFIG, "on")
expect(RECORDS[0]["proxied"] is True, "proxy on restaura al instante")
expect(blg.load_state()["manual"] == "auto", "proxy on retira el modo manual")

# 7. check_blocks: min_isps, modo own_ip y datos obsoletos.
blg.check_blocks = REAL_CHECK_BLOCKS
def fake_fetch(responses):
    def fetch(url, limit=None):
        key = url.rsplit("/", 1)[-1]
        return responses.get(key, (set(), 0, ""))
    return fetch

blg.fetch_ip_list = fake_fetch({
    "blocked-any.txt": ({"9.9.9.9", "8.8.8.8"}, CLOCK[0], ""),
    "blocked-movistar.txt": ({"9.9.9.9"}, CLOCK[0], ""),
    "blocked-vodafone.txt": ({"8.8.8.8"}, CLOCK[0], ""),
    "blocked-orange.txt": (set(), CLOCK[0], ""),
    "blocked-masmovil.txt": (set(), CLOCK[0], ""),
    "blocked-digi.txt": (set(), CLOCK[0], ""),
})
r = blg.check_blocks(CONFIG, set())
expect(r["blocked"] is True and r["blocked_isps"] == 0, "min_isps=1 no pide desglose")
cfg2 = json.loads(json.dumps(CONFIG)); cfg2["detection"]["min_isps"] = 3
r = blg.check_blocks(cfg2, set())
expect(r["blocked"] is False and sorted(r["isp_names"]) == ["Movistar", "Vodafone"], "min_isps=3 filtra por ISPs")
cfg2["detection"]["mode"] = "own_ip"; cfg2["detection"]["min_isps"] = 1
r = blg.check_blocks(cfg2, {"7.7.7.7"})
expect(r["blocked"] is False and r["source"] == "txt" and r["blocked_ips"] == 0, "own_ip sin coincidencias")
r = blg.check_blocks(cfg2, {"8.8.8.8"})
expect(r["blocked"] is True and r["isp_names"] == ["Vodafone"], "own_ip solo cuenta sus IPs")

blg.fetch_ip_list = fake_fetch({
    "blocked-any.txt": (set(), CLOCK[0] - 4 * 3600, ""),
})
r = blg.check_blocks(CONFIG, set())
expect(bool(r["error"]) and r["source"] == "txt (obsoleto)", "datos de hace 4 h se rechazan")
blg.fetch_ip_list = fake_fetch({"blocked-any.txt": (set(), 0, "")})
r = blg.check_blocks(CONFIG, set())
expect(r["error"] == "" and r["blocked"] is False, "sin Last-Modified se acepta la respuesta")

# 8. Modo web: misma regla que la portada de hayahora.futbol.
def web_entry(ip, isp, states, desc="Cloudflare"):
    stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(CLOCK[0]))
    return {"ip": ip, "isp": isp, "description": desc,
            "stateChanges": [{"timestamp": stamp, "state": s} for s in states]}

def fake_http_json(payload, status=200):
    body = json.dumps(payload).encode("utf-8")
    def _http(url, method="GET", headers=None, payload=None, timeout=20, retries=3, limit=None):
        return status, {}, body
    return _http

stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(CLOCK[0]))
cfg_web = json.loads(json.dumps(CONFIG)); cfg_web["detection"]["mode"] = "web"

def over_two(count):
    return [web_entry("10.0.0.%d" % n, isp, [True])
            for n in range(count) for isp in ("Movistar", "Vodafone", "Orange")]

blg.http = fake_http_json({"lastUpdate": stamp, "data": []})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is False and r["source"] == "web(r=0,par=no)", "web sin datos no bloquea")

blg.http = fake_http_json({"lastUpdate": stamp, "data": over_two(10)})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is False and r["blocked_ips"] == 10, "web: 10 IPs x 3 ISPs no basta")

blg.http = fake_http_json({"lastUpdate": stamp, "data": over_two(11)})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is True, "web: 11 IPs x 3 ISPs bloquea")

single = [web_entry("10.0.1.%d" % n, "Movistar", [True]) for n in range(29)]
single.append(web_entry("10.0.2.1", "Vodafone", [True]))
blg.http = fake_http_json({"lastUpdate": stamp, "data": single})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is False and r["blocked_ips"] == 30
       and r["isp_names"] == ["Movistar(29)", "Vodafone(1)"],
       "web: cola de un solo ISP no bloquea")

blg.http = fake_http_json({"lastUpdate": stamp, "data": [
    web_entry("188.114.96.5", "Movistar", [True]),
    web_entry("188.114.97.5", "Vodafone", [True]),
]})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is True, "web: el par Cloudflare bloqueado bloquea")

blg.http = fake_http_json({"lastUpdate": stamp, "data": [
    web_entry("188.114.96.5", "Movistar", [True]),
]})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked"] is False, "web: medio par no bloquea")

blg.http = fake_http_json({"lastUpdate": stamp,
                           "data": over_two(11) + [web_entry("10.0.9.1", "Orange", [True, False])]})
r = blg.check_blocks(cfg_web, set())
expect(r["blocked_ips"] == 11, "web: manda el ultimo stateChange, no el historico")

blg.http = fake_http_json({"lastUpdate": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(CLOCK[0] - 4 * 3600)),
                           "data": over_two(11)})
r = blg.check_blocks(cfg_web, set())
expect(bool(r["error"]) and r["source"] == "web (obsoleto)" and r["blocked"] is False,
       "web: data.json obsoleto no bloquea")

blg.http = fake_http_json({"lastUpdate": stamp, "data": over_two(11)}, status=500)
r = blg.check_blocks(cfg_web, set())
expect("500" in r["error"] and r["blocked"] is False, "web: error HTTP no bloquea")

# 9. Hooks de transicion: una vez por cambio, reintento si fallan, dry-run no ejecuta.
HOOK = os.path.join(STATE_DIR, "hook.sh")
HOOK_LOG = os.path.join(STATE_DIR, "hook.log")
with open(HOOK, "w") as fh:
    fh.write('#!/bin/sh\necho "$1" >> "$2"\n')
os.chmod(HOOK, 0o755)
cfg_hook = json.loads(json.dumps(CONFIG))
cfg_hook["hooks"] = {"on_blocked": [HOOK, "blocked", HOOK_LOG],
                     "on_clear": [HOOK, "clear", HOOK_LOG], "timeout_seconds": 10}

blg.check_blocks = lambda cfg, own: dict(SOURCE)
st = blg.default_state()
SOURCE.update(blocked=False, error="", blocked_ips=0)
blg.apply_cycle(cfg_hook, st)
expect(open(HOOK_LOG).read().split() == ["clear"], "hook on_clear en el primer ciclo")

blg.apply_cycle(cfg_hook, st)
expect(open(HOOK_LOG).read().split() == ["clear"], "no repite el hook sin transicion")

SOURCE.update(blocked=True, blocked_ips=5)
blg.apply_cycle(cfg_hook, st)
expect(open(HOOK_LOG).read().split() == ["clear", "blocked"], "hook on_blocked al detectar")

cfg_fail = json.loads(json.dumps(cfg_hook))
cfg_fail["hooks"]["on_clear"] = ["/bin/false"]
SOURCE.update(blocked=False, blocked_ips=0)
blg.apply_cycle(cfg_fail, st)
expect(open(HOOK_LOG).read().split() == ["clear", "blocked"], "un hook fallido no se da por ejecutado")
expect(st["hook_state"] is True, "mantiene hook_state para reintentar")

blg.apply_cycle(cfg_hook, st)
expect(open(HOOK_LOG).read().split() == ["clear", "blocked", "clear"], "reintenta y ejecuta")

before = open(HOOK_LOG).read()
st_dry = blg.default_state()
SOURCE.update(blocked=True, blocked_ips=5)
blg.apply_cycle(cfg_hook, st_dry, dry_run=True)
expect(open(HOOK_LOG).read() == before and st_dry["hook_state"] is None, "dry-run no ejecuta hooks")

st_err = blg.default_state()
st_err["blocked"] = True
st_err["hook_state"] = True
blg.check_blocks = lambda cfg, own: {"blocked": False, "error": "fuente caida",
                                     "blocked_ips": 0, "blocked_isps": 0, "isp_names": [],
                                     "mode": "web", "source": "web (error)", "last_update": 0}
blg.apply_cycle(cfg_hook, st_err)
expect(st_err["blocked"] is True, "un error de fuente no cambia el estado de bloqueo")
expect(open(HOOK_LOG).read() == before, "un error de fuente no dispara hooks")

shutil.rmtree(STATE_DIR)
print("\nTodos los escenarios OK")
