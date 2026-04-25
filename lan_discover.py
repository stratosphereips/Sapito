#!/usr/bin/env python3
"""
LAN discovery helper for Sapito-style investigations.

What it does (best-effort; depends on what hosts advertise/respond to):
- ARP scan: finds IP<->MAC for hosts in an IPv4 subnet (L2-local).
- mDNS/DNS-SD (Bonjour): discovers advertised services and resolves them to IP/port/TXT.
- SSDP/UPnP: discovers devices responding to M-SEARCH.
- NBNS (NetBIOS): queries node status for NetBIOS names on hosts (mostly Windows/Samba).

Requires elevated privileges for some operations (ARP and raw sockets), depending on OS.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import macvendor
from scapy.all import ARP, Ether, IP, UDP, conf, sendp, sr1, srp
from scapy.layers.netbios import NBNSHeader, NBNSNodeStatusRequest, NBNSNodeStatusResponse
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf


def _normalize_dns_name(name: str) -> str:
    n = (name or "").strip()
    if not n:
        return ""
    return n[:-1] if n.endswith(".") else n


def _load_mdns_service_descriptions(path: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "#" in s:
                    left, right = s.split("#", 1)
                    key = left.strip().rstrip(".")
                    desc = right.strip()
                else:
                    key = s.rstrip(".")
                    desc = ""
                if key:
                    mapping[key] = desc
    except Exception:
        return {}
    return mapping


SERVICE_TYPE_DESCRIPTIONS = _load_mdns_service_descriptions(
    os.path.join(os.path.dirname(__file__), "mDNS-services.txt")
)


def _describe_service_type(service_type: str) -> str:
    st = _normalize_dns_name(service_type)
    return SERVICE_TYPE_DESCRIPTIONS.get(st, "")


@dataclass
class ServiceObservation:
    proto: str  # mdns/ssdp
    service_type: str
    instance: str = ""
    port: Optional[int] = None
    properties: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class HostObservation:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostnames: set[str] = field(default_factory=set)
    services: list[ServiceObservation] = field(default_factory=list)
    nbns_names: set[str] = field(default_factory=set)
    ssdp: dict[str, set[str]] = field(default_factory=lambda: {})

    def add_ssdp_header(self, k: str, v: str) -> None:
        k2 = (k or "").strip().upper()
        v2 = (v or "").strip()
        if not k2 or not v2:
            return
        self.ssdp.setdefault(k2, set()).add(v2)


def _get_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    try:
        return macvendor.get_all(mac.upper()).manuf_long
    except Exception:
        return None


def arp_scan(subnet: str, iface: Optional[str], timeout: float = 2.0) -> dict[str, HostObservation]:
    net = ipaddress.ip_network(subnet, strict=False)
    if net.version != 4:
        raise ValueError("ARP scan supports only IPv4 subnets.")

    conf.verb = 0
    broadcast = "ff:ff:ff:ff:ff:ff"
    pkt = Ether(dst=broadcast) / ARP(pdst=str(net))
    ans, _ = srp(pkt, iface=iface, timeout=timeout, inter=0.02)

    hosts: dict[str, HostObservation] = {}
    for _, rcv in ans:
        ip = getattr(rcv, "psrc", None)
        mac = getattr(rcv, "hwsrc", None)
        if not ip:
            continue
        obs = hosts.get(ip) or HostObservation(ip=ip)
        if mac:
            obs.mac = mac.upper()
            obs.vendor = _get_vendor(obs.mac)
        hosts[ip] = obs
    return hosts


def nbns_node_status(ip: str, iface: Optional[str], timeout: float = 0.8) -> set[str]:
    """
    Query NBNS node status to get a host's NetBIOS names (Windows/Samba).
    This is sent unicast to the target IP.
    """
    conf.verb = 0
    try:
        tid = random.randint(0, 0xFFFF)
        pkt = IP(dst=ip) / UDP(sport=random.randint(1024, 65535), dport=137) / NBNSHeader(TID=tid) / NBNSNodeStatusRequest()
        resp = sr1(pkt, iface=iface, timeout=timeout, retry=0)
        if resp is None:
            return set()
        if NBNSNodeStatusResponse not in resp:
            return set()
        r = resp[NBNSNodeStatusResponse]
        names: set[str] = set()
        for e in getattr(r, "NODE_NAME", []) or []:
            n = getattr(e, "NAME", None)
            if not n:
                continue
            n2 = n.decode("utf-8", "replace").strip() if isinstance(n, (bytes, bytearray)) else str(n).strip()
            if n2:
                names.add(n2)
        return names
    except PermissionError:
        return set()
    except Exception:
        return set()


SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900


def ssdp_discover(iface: Optional[str], timeout: float = 2.0) -> dict[str, dict[str, set[str]]]:
    """
    Sends SSDP M-SEARCH and parses responses (best-effort).
    Returns mapping: ip -> headers map.
    """
    # Use a normal UDP socket; no raw needed.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        # Some OSes require binding to iface/IP explicitly; we keep it simple and best-effort.
        sock.bind(("", 0))
    except Exception:
        pass

    # M-SEARCH for all devices
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode("utf-8", "replace")

    try:
        sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
    except Exception:
        sock.close()
        return {}

    results: dict[str, dict[str, set[str]]] = {}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, (srcip, _srcport) = sock.recvfrom(65535)
        except socket.timeout:
            break
        except Exception:
            break
        txt = data.decode("utf-8", "replace")
        headers: dict[str, set[str]] = results.get(srcip) or {}
        for line in txt.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k2 = k.strip().upper()
            v2 = v.strip()
            if k2 and v2:
                headers.setdefault(k2, set()).add(v2)
        results[srcip] = headers
    sock.close()
    return results


class _ZCListener(ServiceListener):
    def __init__(self, zc: Zeroconf, out: dict[str, list[ServiceInfo]]):
        self.zc = zc
        self.out = out

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        try:
            info = zc.get_service_info(type_, name, timeout=1500)
        except Exception:
            info = None
        if info is not None:
            self.out.setdefault(type_, []).append(info)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        return


def mdns_discover(duration: float = 4.0) -> dict[str, list[ServiceInfo]]:
    """
    Uses zeroconf to browse all service types via _services._dns-sd._udp.local,
    then browses each discovered type and resolves instances.
    Returns mapping: service_type -> list(ServiceInfo)
    """
    zc = Zeroconf()
    discovered: dict[str, list[ServiceInfo]] = {}

    # Phase 1: discover service types
    types_out: dict[str, list[ServiceInfo]] = {}
    types_listener = _ZCListener(zc, types_out)
    ServiceBrowser(zc, "_services._dns-sd._udp.local.", types_listener)
    time.sleep(max(0.5, duration / 2.0))

    service_types: set[str] = set()
    for infos in types_out.values():
        for info in infos:
            # PTR records appear as ServiceInfo with "name" including the discovered type.
            n = _normalize_dns_name(getattr(info, "name", ""))
            if n.endswith(".local") and "._" in n:
                # For _services browsing, "n" itself is the advertised type.
                service_types.add(n if n.startswith("_") else n.split(".", 1)[-1])

    # Fallback: if the above yields nothing (some stacks), use a small default set.
    if not service_types:
        service_types = {
            "_workstation._tcp.local.",
            "_ssh._tcp.local.",
            "_smb._tcp.local.",
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_companion-link._tcp.local.",
            "_googlecast._tcp.local.",
            "_spotify-connect._tcp.local.",
        }

    # Phase 2: browse each type and resolve instances
    for st in sorted(service_types):
        listener = _ZCListener(zc, discovered)
        try:
            ServiceBrowser(zc, st, listener)
        except Exception:
            continue

    time.sleep(max(0.5, duration / 2.0))
    zc.close()
    return discovered


def _serviceinfo_addresses(info: ServiceInfo) -> list[str]:
    addrs: list[str] = []
    try:
        for a in info.addresses or []:
            addrs.append(socket.inet_ntoa(a))
    except Exception:
        pass
    try:
        for a6 in getattr(info, "addresses_by_version", lambda *_: [])(socket.AF_INET6):
            addrs.append(socket.inet_ntop(socket.AF_INET6, a6))
    except Exception:
        pass
    # De-dupe stable order
    out: list[str] = []
    for a in addrs:
        if a not in out:
            out.append(a)
    return out


def _serviceinfo_properties(info: ServiceInfo) -> dict[str, str]:
    props: dict[str, str] = {}
    try:
        for k, v in (info.properties or {}).items():
            ks = k.decode("utf-8", "replace") if isinstance(k, (bytes, bytearray)) else str(k)
            vs = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
            props[ks] = vs
    except Exception:
        return {}
    return props


def merge_mdns(hosts: dict[str, HostObservation], mdns: dict[str, list[ServiceInfo]]) -> None:
    for st, infos in mdns.items():
        stn = _normalize_dns_name(st)
        desc = _describe_service_type(stn)
        for info in infos:
            instance = _normalize_dns_name(getattr(info, "name", ""))
            server = _normalize_dns_name(getattr(info, "server", "")) if hasattr(info, "server") else ""
            port = getattr(info, "port", None)
            props = _serviceinfo_properties(info)
            addrs = _serviceinfo_addresses(info)

            for ip in addrs:
                obs = hosts.get(ip) or HostObservation(ip=ip)
                if server:
                    obs.hostnames.add(server)
                obs.services.append(
                    ServiceObservation(
                        proto="mdns",
                        service_type=stn,
                        instance=instance,
                        port=int(port) if isinstance(port, int) else None,
                        properties=props,
                        description=desc,
                    )
                )
                hosts[ip] = obs


def merge_ssdp(hosts: dict[str, HostObservation], ssdp: dict[str, dict[str, set[str]]]) -> None:
    for ip, headers in ssdp.items():
        obs = hosts.get(ip) or HostObservation(ip=ip)
        for k, vs in headers.items():
            for v in vs:
                obs.add_ssdp_header(k, v)
        # Represent SSDP as "services" too (so output is consistent).
        st_vals = sorted(obs.ssdp.get("ST", set()))
        for st in st_vals:
            obs.services.append(
                ServiceObservation(
                    proto="ssdp",
                    service_type=st,
                    instance="",
                    port=None,
                    properties={},
                    description="SSDP/UPnP advertisement",
                )
            )
        hosts[ip] = obs


def to_json(hosts: dict[str, HostObservation]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    def _sort_key(s: str):
        a = ipaddress.ip_address(s)
        return (a.version, int(a))

    for ip in sorted(hosts.keys(), key=_sort_key):
        h = hosts[ip]
        out.append(
            {
                "ip": h.ip,
                "mac": h.mac,
                "vendor": h.vendor,
                "hostnames": sorted(h.hostnames),
                "nbns_names": sorted(h.nbns_names),
                "services": [
                    {
                        "proto": s.proto,
                        "service_type": s.service_type,
                        "description": s.description,
                        "instance": s.instance,
                        "port": s.port,
                        "properties": s.properties,
                    }
                    for s in h.services
                ],
                "ssdp_headers": {k: sorted(vs) for k, vs in sorted(h.ssdp.items())},
            }
        )
    return out


def print_table(hosts: dict[str, HostObservation]) -> None:
    def _sort_key(s: str):
        a = ipaddress.ip_address(s)
        return (a.version, int(a))

    for ip in sorted(hosts.keys(), key=_sort_key):
        h = hosts[ip]
        mac = h.mac or "-"
        vendor = h.vendor or "-"
        names = ", ".join(sorted(h.hostnames)) if h.hostnames else "-"
        nbns = ", ".join(sorted(h.nbns_names)) if h.nbns_names else "-"
        print(f"{ip}\n  mac={mac} vendor={vendor}\n  hostnames={names}\n  nbns={nbns}")
        if h.services:
            print("  services:")
            for s in h.services:
                d = f" ↳ {s.description}" if s.description else ""
                inst = f" {s.instance}" if s.instance else ""
                port = f":{s.port}" if s.port else ""
                print(f"    - [{s.proto}] {s.service_type}{d}{inst}{port}")
        if h.ssdp:
            # Don't spam; show key summary.
            st = ", ".join(sorted(h.ssdp.get("ST", set()))) if h.ssdp.get("ST") else ""
            usn = ", ".join(sorted(h.ssdp.get("USN", set()))) if h.ssdp.get("USN") else ""
            loc = ", ".join(sorted(h.ssdp.get("LOCATION", set()))) if h.ssdp.get("LOCATION") else ""
            if st or usn or loc:
                print(f"  ssdp: ST={st or '-'} USN={usn or '-'} LOCATION={loc or '-'}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="LAN discovery using ARP + mDNS + SSDP + NBNS.")
    parser.add_argument("--iface", "-i", help="Network interface (optional)", default=None)
    parser.add_argument("--subnet", "-s", help="IPv4 subnet for ARP scan (e.g. 192.168.1.0/24)", default=None)
    parser.add_argument("--no-arp", action="store_true", help="Skip ARP scan")
    parser.add_argument("--no-mdns", action="store_true", help="Skip mDNS/DNS-SD discovery")
    parser.add_argument("--no-ssdp", action="store_true", help="Skip SSDP discovery")
    parser.add_argument("--no-nbns", action="store_true", help="Skip NBNS node-status queries (requires IP list)")
    parser.add_argument("--duration", "-t", type=float, default=4.0, help="Discovery duration for mDNS/SSDP (seconds)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)

    macvendor.refresh()

    hosts: dict[str, HostObservation] = {}

    if not args.no_arp:
        if not args.subnet:
            print("error: --subnet is required for ARP scan (or pass --no-arp).", file=sys.stderr)
            return 2
        try:
            hosts.update(arp_scan(args.subnet, args.iface))
        except PermissionError:
            print("warning: ARP scan needs elevated privileges; skipping ARP.", file=sys.stderr)
        except Exception as e:
            print(f"warning: ARP scan failed: {e}", file=sys.stderr)

    if not args.no_mdns:
        try:
            mdns = mdns_discover(duration=max(1.0, float(args.duration)))
            merge_mdns(hosts, mdns)
        except Exception as e:
            print(f"warning: mDNS discovery failed: {e}", file=sys.stderr)

    if not args.no_ssdp:
        try:
            ssdp = ssdp_discover(args.iface, timeout=max(1.0, float(args.duration)))
            merge_ssdp(hosts, ssdp)
        except Exception as e:
            print(f"warning: SSDP discovery failed: {e}", file=sys.stderr)

    if not args.no_nbns and hosts:
        for ip, h in list(hosts.items()):
            try:
                names = nbns_node_status(ip, args.iface)
                h.nbns_names |= names
                hosts[ip] = h
            except Exception:
                continue

    if args.json:
        print(json.dumps(to_json(hosts), indent=2, sort_keys=True))
    else:
        print_table(hosts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
