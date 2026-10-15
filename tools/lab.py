"""Laboratoire réseau sans droits root : un vrai réseau virtuel (VLAN 802.1Q, routeur, hôtes avec services) pour tester Panther.

Tout vit dans des espaces de noms réseau créés avec `unshare -Urn` (aucun `sudo`, rien ne touche à votre vrai réseau) :

    scanneur (S) ──s0─── pont du routeur (R) ───hl─── hôtes du LAN (H)     192.168.1.0/24 (non étiqueté)
        │ s0.30 (VLAN 30)      │  br.30 192.168.30.1                         192.168.30.0/24 (VLAN 30, étiqueté)
        │                      └─ r20.20 192.168.20.1 ─── hôtes (V)          192.168.20.0/24 (VLAN 20, derrière le routeur)

Usage : `python3 tools/lab.py [--hosts N] [--keep]` lance un scan complet et affiche le résultat en JSON.
Les tests (`tests/test_lab.py`) l'utilisent par `run_scenario`. Les noms, MAC et services sont fictifs.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Hôtes fictifs : (réseau, dernier octet, services). Un service = (port, genre).
LAN = {
    10: [(80, "http:Caméra salon"), (554, "rtsp-open")],
    11: [(6379, "redis-open")],
    12: [(23, "banner:login:")],
    13: [(22, "banner:SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")],
    14: [(80, "http:Imprimante")],
    15: [(6379, "redis-protected")],
    16: [],
}
VLAN20 = {10: [(80, "http:Serveur VLAN 20"), (22, "banner:SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")], 11: []}
VLAN30 = {10: [(80, "http:Domotique"), (1883, "banner:")]}


def sh(cmd, ns=None, check=True):
    """Commande dans l'espace de noms `ns` (PID d'un processus qui l'habite) ou le courant."""
    full = ["nsenter", "-t", str(ns), "-n", "--"] + cmd if ns else cmd
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)} : {r.stderr.strip()}")
    return r


def ip(args, ns=None, check=True):
    return sh(["ip"] + args.split(), ns, check)


def sysctl(key, value, ns=None):
    sh(["sh", "-c", f"echo {value} > /proc/sys/{key.replace('.', '/')}"], ns)


def available():
    """Vrai si les espaces de noms sans privilèges fonctionnent ici (outil `unshare`/`ip`/`nsenter`, noyau le permettant)."""
    if not all(shutil.which(t) for t in ("unshare", "ip", "nsenter")):
        return False
    r = subprocess.run(["unshare", "-Urn", "sh", "-c", "ip link add name t0 type veth peer name t1 && ip link add link t0 name t0.5 type vlan id 5"],
                       capture_output=True, text=True)
    return r.returncode == 0


class Lab:
    """Construit la topologie. À utiliser dans un processus déjà lancé par `unshare -Urn` (voir `run_scenario`)."""

    def __init__(self, extra_lan=0):
        self.procs = []
        self.extra_lan = extra_lan

    def sleeper(self):
        p = subprocess.Popen(["unshare", "-n", "sleep", "infinity"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        for _ in range(100):  # le temps que l'espace de noms existe réellement
            if os.path.exists(f"/proc/{p.pid}/ns/net") and subprocess.run(["readlink", f"/proc/{p.pid}/ns/net"], capture_output=True, text=True).stdout != \
                    subprocess.run(["readlink", "/proc/self/ns/net"], capture_output=True, text=True).stdout:
                break
            time.sleep(0.02)
        return p.pid

    def build(self):
        self.R, self.H, self.V = self.sleeper(), self.sleeper(), self.sleeper()
        R, H, V = self.R, self.H, self.V
        for ns in (R, H, V, None):
            ip("link set lo up", ns)
        ip("link add name s0 type veth peer name rs0")
        ip(f"link set rs0 netns {R}")
        # côté routeur : pont, liens vers H (LAN) et vers V (VLAN 20)
        ip("link add name rh type veth peer name hl", R)
        ip(f"link set hl netns {H}", R)
        ip("link add name r20 type veth peer name v20", R)
        ip(f"link set v20 netns {V}", R)
        ip("link add name lanbr type bridge", R)
        for port in ("rs0", "rh"):
            ip(f"link set {port} master lanbr", R)
            ip(f"link set {port} up", R)
        ip("addr add 192.168.1.1/24 dev lanbr", R)
        ip("link set lanbr up", R)
        ip("link add link lanbr name lanbr.30 type vlan id 30", R)
        ip("addr add 192.168.30.1/24 dev lanbr.30", R)
        ip("link set lanbr.30 up", R)
        ip("link set r20 up", R)
        ip("link add link r20 name r20.20 type vlan id 20", R)
        ip("addr add 192.168.20.1/24 dev r20.20", R)
        ip("link set r20.20 up", R)
        sysctl("net.ipv4.ip_forward", 1, R)
        # scanneur
        ip("addr add 192.168.1.2/24 dev s0")
        ip("link set s0 up")
        ip("link add link s0 name s0.30 type vlan id 30")
        ip("addr add 192.168.30.2/24 dev s0.30")
        ip("link set s0.30 up")
        ip("route add default via 192.168.1.1 dev s0")
        # hôtes : un macvlan (donc une MAC) par adresse, chacun ne répond ARP que pour la sienne
        ip("link set hl up", H)
        ip("link add link hl name hl.30 type vlan id 30", H)
        ip("link set hl.30 up", H)
        ip("link set v20 up", V)
        ip("link add link v20 name v20.20 type vlan id 20", V)
        ip("link set v20.20 up", V)
        for ns in (H, V):
            sysctl("net.ipv4.conf.all.arp_ignore", 1, ns)
            sysctl("net.ipv4.conf.all.arp_announce", 2, ns)
        lan = dict(LAN)
        for i in range(self.extra_lan):
            lan[20 + i] = []  # 20 à 253 : jusqu'à 234 appareils muets en plus
        self.macvlans(H, "hl", "192.168.1", lan, via="192.168.1.1")
        self.macvlans(H, "hl.30", "192.168.30", VLAN30)
        self.macvlans(V, "v20.20", "192.168.20", VLAN20, via="192.168.20.1")
        for ns, hosts, net in ((H, lan, "192.168.1"), (H, VLAN30, "192.168.30"), (V, VLAN20, "192.168.20")):
            spec = {f"{net}.{last}": svc for last, svc in hosts.items() if svc}
            if spec:
                p = subprocess.Popen(["nsenter", "-t", str(ns), "-n", "--", sys.executable, os.path.abspath(__file__), "--services", json.dumps(spec)])
                self.procs.append(p)
        time.sleep(0.5)  # le temps que les services écoutent
        return self

    def macvlans(self, ns, parent, net, hosts, via=None):
        self.macs = getattr(self, "macs", {})
        for last in hosts:
            name = f"m{parent.replace('.', '_')[-6:]}{last}"[:15]
            ip(f"link add link {parent} name {name} type macvlan mode bridge", ns)
            ip(f"addr add {net}.{last}/24 dev {name}", ns)
            ip(f"link set {name} up", ns)
            self.macs[f"{net}.{last}"] = ip(f"-o link show dev {name}", ns).stdout.split("link/ether")[1].split()[0]
        if via:
            ip(f"route add default via {via}", ns, check=False)

    def start_agent(self):
        """Switch administrable fictif (agent SNMP v2c « public » sur 192.168.1.1:161) qui connaît les hôtes du lab :
        ARP du routeur pour le VLAN 20, table des ports (FDB) pour deux hôtes du LAN, noms de ports."""
        data = {"1.3.6.1.2.1.1.5.0": "core-sw", "1.3.6.1.2.1.1.1.0": "Switch de laboratoire",
                "1.3.6.1.2.1.17.7.1.4.3.1.1.1": "LAN", "1.3.6.1.2.1.17.7.1.4.3.1.1.20": "SERVEURS",
                "1.3.6.1.2.1.17.1.4.1.2.3": 10003, "1.3.6.1.2.1.31.1.1.1.1.10003": "Gi1/0/3",
                "1.3.6.1.2.1.17.1.4.1.2.4": 10004, "1.3.6.1.2.1.31.1.1.1.1.10004": "Gi1/0/4"}
        for last in (10, 11):
            data[f"1.3.6.1.2.1.4.22.1.2.5.192.168.20.{last}"] = {"mac": self.macs[f"192.168.20.{last}"]}
        for last, port in ((10, 3), (11, 4)):
            mac = ".".join(str(int(b, 16)) for b in self.macs[f"192.168.1.{last}"].split(":"))
            data[f"1.3.6.1.2.1.17.7.1.2.2.1.2.1.{mac}"] = port
        self.procs.append(subprocess.Popen(["nsenter", "-t", str(self.R), "-n", "--", sys.executable, os.path.abspath(__file__), "--agent", json.dumps(data)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)

    def send_frames(self, iface, frames):
        """Envoie des trames Ethernet brutes sur `iface` du routeur (vraie émission : le scanneur les reçoit par AF_PACKET)."""
        code = ("import socket,sys\ns=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\ns.bind((sys.argv[1],0))\n"
                "for f in sys.argv[2:]: s.send(bytes.fromhex(f))")
        sh([sys.executable, "-c", code, iface] + [f.hex() for f in frames], self.R)

    def close(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()

    def __enter__(self):
        return self.build()

    def __exit__(self, *exc):
        self.close()


# ---- trames LLDP / CDP (construites à la main, comme le ferait un switch) ----------------------------------------------

def lldp_frame(src="00:11:22:33:44:55", name="core-sw", port="Gi1/0/3", mgmt="192.168.1.1", vlan=20, vlan_name="SERVEURS"):
    def tlv(t, v):
        return ((t << 9) | len(v)).to_bytes(2, "big") + v
    mac = bytes.fromhex(src.replace(":", ""))
    body = (tlv(1, b"\x04" + mac) + tlv(2, b"\x05" + port.encode()) + tlv(3, (120).to_bytes(2, "big")) + tlv(5, name.encode())
            + tlv(8, bytes([5, 1]) + bytes(map(int, mgmt.split("."))) + b"\x02" + (1).to_bytes(4, "big") + b"\x00")
            + tlv(127, b"\x00\x80\xc2\x01" + vlan.to_bytes(2, "big"))
            + tlv(127, b"\x00\x80\xc2\x03" + vlan.to_bytes(2, "big") + bytes([len(vlan_name)]) + vlan_name.encode()) + tlv(0, b""))
    return bytes.fromhex("0180c200000e") + mac + b"\x88\xcc" + body


def cdp_frame(src="00:11:22:33:44:66", name="dist-sw", port="Gi0/1", platform="cisco WS-C2960", vlan=10, mgmt="192.168.1.253"):
    def tlv(t, v):
        return t.to_bytes(2, "big") + (len(v) + 4).to_bytes(2, "big") + v
    cdp = (bytes([2, 180, 0, 0]) + tlv(1, name.encode()) + tlv(3, port.encode()) + tlv(6, platform.encode()) + tlv(10, vlan.to_bytes(2, "big"))
           + tlv(2, (1).to_bytes(4, "big") + bytes([1, 1, 0xCC]) + (4).to_bytes(2, "big") + bytes(map(int, mgmt.split(".")))))
    payload = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
    return bytes.fromhex("01000ccccccc") + bytes.fromhex(src.replace(":", "")) + len(payload).to_bytes(2, "big") + payload


# ---- faux services (exécutés dans l'espace de noms des hôtes) -------------------------------------------------------

def serve(spec):
    def handle(conn, kind):
        try:
            conn.settimeout(2)
            if kind.startswith("banner:"):
                conn.sendall(kind[7:].encode() + b"\r\n")
                conn.recv(100)
            elif kind.startswith("http:"):
                conn.recv(2048)
                body = f"<html><head><title>{kind[5:]}</title></head><body>ok</body></html>".encode()
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: lab-httpd\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            elif kind == "redis-open":
                if conn.recv(100).upper().startswith(b"PING"):
                    conn.sendall(b"+PONG\r\n")
            elif kind == "redis-protected":
                conn.recv(100)
                conn.sendall(b"-NOAUTH Authentication required.\r\n")
            elif kind == "rtsp-open":
                conn.recv(2048)
                conn.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    def listen(addr, port, kind):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(32)
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c, kind), daemon=True).start()
    for addr, services in spec.items():
        for port, kind in services:
            threading.Thread(target=listen, args=(addr, port, kind), daemon=True).start()
    threading.Event().wait()


def agent(data):
    """Agent SNMP de laboratoire (dans l'espace de noms du routeur). Valeurs : entier, texte ou {"mac": "aa:bb:…"}."""
    from tests.test_snmp import FakeAgent
    conv = {k: bytes.fromhex(v["mac"].replace(":", "")) if isinstance(v, dict) else v.encode() if isinstance(v, str) else v for k, v in data.items()}
    FakeAgent(conv, host="0.0.0.0", port=161).run()


# ---- scénario : scan complet depuis S ---------------------------------------------------------------------------------

def scenario(extra_lan=0, depth="normal", security=True, targets=("192.168.20.0/24",), snmp=False):
    from panther import networks
    from panther.scanner import Scanner
    tmp = tempfile.mkdtemp()
    os.environ["XDG_CONFIG_HOME"] = tmp
    out = {}
    with Lab(extra_lan) as lab:
        local = "192.168.1.0/24"
        auto = networks.auto_targets(local)
        out["auto_targets"] = auto
        out["vlan_ids"] = networks.vlan_ids()
        sc = Scanner()
        sources = []
        if snmp:
            lab.start_agent()
            sources = [{"host": "192.168.1.1", "community": "public"}]
        t0 = time.time()
        sc.start(list(targets) + auto, sources, depth, security)
        while sc.snapshot()["status"] == "scanning":
            time.sleep(0.2)
        snap = sc.snapshot()
        out.update(duration=round(time.time() - t0, 1), status=snap["status"], error=snap["error"], warnings=snap["warnings"],
                   networks=snap["networks"], paths=snap["paths"], network=snap["network"])
        out["snmp"] = snap["snmp"]
        out["devices"] = [{k: d.get(k) for k in ("ip", "mac", "type", "network", "vlan", "ports", "hostname", "path", "is_gateway", "is_self", "is_switch", "switch", "switch_port")}
                          | {"security": [f["id"] for f in d.get("security") or []]} for d in snap["devices"]]
        out["lab"] = {"R": lab.R}
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def lldp_scenario():
    """Un « switch » émet de vraies trames LLDP puis CDP vers le scanneur, qui les capte par AF_PACKET."""
    from panther import topology
    result = {}
    with Lab() as lab:
        t = threading.Thread(target=lambda: result.update(zip(("status", "neighbors"), topology.sniff_neighbors("s0", 4))))
        t.start()
        time.sleep(1)
        lab.send_frames("rs0", [lldp_frame(), cdp_frame()])
        t.join()
    return result


def run_scenario(extra_lan=0, depth="normal", security=True, targets=("192.168.20.0/24",), snmp=False, timeout=300, name="scenario"):
    """Lance `scenario` dans un `unshare -Urn` et renvoie son résultat (dict)."""
    cmd = ["unshare", "-Urn", sys.executable, os.path.abspath(__file__), f"--{name}", json.dumps({"extra_lan": extra_lan, "depth": depth, "security": security, "targets": list(targets), "snmp": snmp} if name == "scenario" else {})]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
    if r.returncode:
        raise RuntimeError(r.stderr[-2000:] or r.stdout[-2000:])
    return json.loads(r.stdout.splitlines()[-1])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hosts", type=int, default=0, help="hôtes supplémentaires sur le LAN (test de charge)")
    ap.add_argument("--depth", default="normal")
    ap.add_argument("--services", help=argparse.SUPPRESS)
    ap.add_argument("--scenario", help=argparse.SUPPRESS)
    ap.add_argument("--lldp", help=argparse.SUPPRESS)
    ap.add_argument("--agent", help=argparse.SUPPRESS)
    ap.add_argument("--snmp", action="store_true", help="ajoute un switch SNMP fictif (core-sw) sur le routeur")
    a = ap.parse_args()
    if a.services:
        serve({k: [tuple(s) for s in v] for k, v in json.loads(a.services).items()})
    elif a.agent:
        agent(json.loads(a.agent))
    elif a.lldp:
        print(json.dumps(lldp_scenario()))
    elif a.scenario:
        print(json.dumps(scenario(**json.loads(a.scenario))))
    else:
        if not available():
            sys.exit("Espaces de noms sans privilèges indisponibles ici.")
        print(json.dumps(run_scenario(a.hosts, a.depth, snmp=a.snmp), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
