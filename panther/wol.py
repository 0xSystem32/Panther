"""Wake-on-LAN : « paquet magique » pour réveiller un appareil éteint ou en veille (s'il est configuré pour).

Le paquet (6 × 0xFF puis 16 × l'adresse MAC) est envoyé en diffusion UDP sur le réseau local. Ça ne marche que si l'appareil
a Wake-on-LAN activé (réglage du BIOS/système) et, en général, qu'il est branché en Ethernet : le Wi-Fi le gère rarement.
Une adresse MAC « privée » (aléatoire) ne peut pas réveiller un appareil : seule son adresse matérielle d'origine le peut.
"""
import ipaddress
import re
import socket


def parse_mac(mac):
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(h) != 12 or not re.fullmatch(r"([0-9a-fA-F]{2}[:\-.]?){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}", (mac or "").strip()):
        raise ValueError(f"adresse MAC invalide : « {mac} »")
    return bytes.fromhex(h)


def magic_packet(mac):
    return b"\xff" * 6 + parse_mac(mac) * 16


def broadcast_for(cidr):
    """Adresse de diffusion d'un réseau (« 192.168.1.0/24 » -> « 192.168.1.255 »)."""
    return str(ipaddress.ip_network(cidr, strict=False).broadcast_address)


def send(mac, broadcasts=("255.255.255.255",), ports=(9, 7)):
    """Envoie le paquet à chaque adresse de diffusion et port. -> nombre de paquets envoyés. Lève ValueError si la MAC est invalide."""
    packet = magic_packet(mac)
    sent = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for addr in broadcasts:
            for port in ports:
                try:
                    s.sendto(packet, (addr, port))
                    sent += 1
                except OSError:
                    continue
    finally:
        s.close()
    return sent
