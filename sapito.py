#!/usr/bin/env python
# Authors:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com
# Veronica Valeros, vero.valeros@gmail.com, valerver@fel.cvut.cz
# Stratosphere Laboratory, Czech Technical University in Prague

import argparse
import macvendor
from scapy.all import *
from datetime import datetime
from zeroconf import _protocol as zproto
import socket
from types import SimpleNamespace

# Default args for import-time use (tests, library usage). Overridden in __main__.
args = SimpleNamespace(verbose=0, debug=0, readfile=None, interface=None, filter=None, summary=False)

# TODO: THis may need to be updated.
apple_devices ={
    'macbook': 'MacBook',
    'J208AP': 'iPad Pro (10.5-inch) (iPad7,4)',
    'J321AP': 'iPad Pro (12.9-inch) (3rd generation) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Its identifier is iPad8,7',
    'J127AP': 'iPad Pro (9.7-inch) (iPad6,3)',
    'J81AP': 'iPad Air 2 (iPad5,3)',
    'J72bAP': 'This is the iPad (6th generation) (iPad7,6)',
    'J71bAP': 'iPad (6th generation) (iPad7,5)',
    'J128AP': 'iPad Pro (9.7-inch) (iPad6,4)',
    'J82AP': 'iPad Air 2 (iPad5,4)',
    'J318AP': 'iPad Pro (11-inch) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage',
    'J96AP': 'iPad mini 4 (iPad5,1)',
    'J207AP': 'iPad Pro (10.5-inch) (iPad7,3)',
    '_homekit': 'Apple Homekit',
    'J420AP': 'iPad Pro 12.9-inch (4th generation)'

}

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    IMPORTANT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # "dim" (not "conceal"), to avoid invisible lines in some terminals
    NORMAL = '\033[2m'

# Store info about the clients
# The format of the clients is: {'MAC': 'name'}
clients = {}

device_observations = {}

KNOWN_TXT_KEYS = {
    # AirPlay / RAOP (reverse engineered / public convention)
    "AirPlay": {
        "model": "Hardware model identifier (Apple)",
        "deviceid": "Device identifier (often Wi‑Fi MAC)",
        "features": "Feature bitmask (AirPlay capabilities)",
        "fex": "Extended features (opaque token)",
        "flags": "Flags bitmask (AirPlay)",
        "protovers": "Protocol version",
        "pk": "Public key / pairing key material (opaque)",
        "pi": "Persistent identifier (UUID-like)",
        "psi": "Pairing/session identifier (UUID-like)",
        "gid": "Group identifier (UUID-like)",
        "act": "Access/control type (numeric)",
        "acl": "Access-control list mode (numeric)",
        "at": "Authentication type (numeric)",
        "gcgl": "Group/capability flag (numeric)",
        "igl": "Group/capability flag (numeric)",
    },
    "RAOP": {
        "am": "Hardware model identifier (Apple)",
        "cn": "Audio channel map / capabilities (comma-separated ints)",
        "da": "Device supports something like DACP/remote? (bool-like)",
        "et": "Encryption types supported (comma-separated ints)",
        "ft": "Feature bitmask (RAOP capabilities)",
        "md": "Metadata types supported (comma-separated ints)",
        "pk": "Public key / pairing key material (opaque)",
        "sf": "Status/flags bitmask",
        "tp": "Transport (e.g., UDP/TCP)",
        "vn": "Version number (numeric)",
        "vs": "Version string (e.g., 940.23.1)",
        "vv": "Variant / feature level (numeric)",
    },
    # Companion Link (Apple proprietary)
    "CompanionLink": {
        "rpBA": "Likely Bluetooth address (BD_ADDR) (MAC-like)",
        "rpAD": "Opaque identifier/token (Apple proprietary)",
        "rpFl": "Flags bitmask (Apple proprietary)",
        "rpHN": "Opaque identifier/token (Apple proprietary)",
        "rpHI": "Opaque identifier/token (Apple proprietary)",
        "rpHA": "Opaque identifier/token (Apple proprietary)",
        "rpVr": "Version string (Apple proprietary)",
        "rpMac": "Unknown (often '0')",
    },
}


def _service_family_from_name(record_name: str) -> str:
    if record_name.endswith("._airplay._tcp.local"):
        return "AirPlay"
    if record_name.endswith("._raop._tcp.local"):
        return "RAOP"
    if record_name.endswith("._companion-link._tcp.local"):
        return "CompanionLink"
    return ""


def _interpret_txt(record_name: str, kv: dict) -> dict:
    """
    Translate known TXT keys into a structured profile snippet.
    Any unknown/proprietary keys remain as-is and are still stored raw.
    """
    family = _service_family_from_name(record_name)
    if not family:
        return {}

    interpreted = {"family": family, "record": record_name, "known": {}, "unknown": {}}
    known_map = KNOWN_TXT_KEYS.get(family, {})
    for k, vs in kv.items():
        if k in known_map:
            interpreted["known"][k] = {
                "meaning": known_map[k],
                "values": sorted(list(vs)),
            }
        else:
            interpreted["unknown"][k] = sorted(list(vs))
    return interpreted


def _get_device_obs(mac: str):
    obs = device_observations.get(mac)
    if obs is None:
        obs = {
            "vendor": None,
            "first_seen": None,
            "last_seen": None,
            "packets_total": 0,
            "packets_mdns": 0,
            "mdns_packets_query": 0,
            "mdns_packets_response": 0,
            "packets_llmnr": 0,
            "packets_ssdp": 0,
            "packets_igmp": 0,
            "ips": set(),
            "names": set(),
            "mdns_self_hostnames": set(),
            "mdns_other_hostnames": set(),
            "mdns_questions": set(),
            "mdns_q_count": 0,
            "mdns_a_count": 0,
            "mdns_service_types": set(),  # _airplay._tcp.local
            "mdns_service_instances_advertised": set(),  # instance with SRV pointing to self
            "mdns_service_instances_referenced": set(),  # instance names seen but not attributable to self
            "mdns_ptr_service": set(),  # (service_type, service_instance)
            "mdns_ptr_reverse": set(),  # (reverse_name, hostname)
            "mdns_ptr_service_q": set(),
            "mdns_ptr_service_r": set(),
            "mdns_ptr_reverse_q": set(),
            "mdns_ptr_reverse_r": set(),
            "mdns_srv": set(),  # (service_instance, target_hostname, port, priority, weight)
            "mdns_a": {},  # hostname -> set(ip)
            "mdns_aaaa": {},  # hostname -> set(ip6)
            "mdns_txt_strings": {},  # record_name -> set(txt_strings)
            "mdns_txt_kv": {},  # record_name -> {k -> set(v)}
            "mdns_txt_interpreted": {},  # record_name -> interpreted dict
            "ssdp_start_lines": set(),
            "ssdp_headers": {},  # header -> set(values)
            "llmnr_questions": set(),
            "llmnr_answers": set(),  # (name, type, rdata)
            "igmp_groups": set(),
            "profile": {
                "airplay": {},
                "raop": {},
                "companion_link": {},
            },
        }
        device_observations[mac] = obs
    return obs

def add_client(shw, srcip, name='unknown'):
    """ Add client to our list"""
    try:
        data = clients[shw]
        if 'unknown' in data['name']:
            data['name'] = name
            clients[shw] = data
    except KeyError:
        data = {}
        data['srcip'] = srcip
        data['name'] = name
        clients[shw] = data

def get_client(shw):
    """ Get the client """
    return clients[shw]

def parse_txt(record):
    if b'Chromecast' in record.text:
        device = 'Chromecast'
        info = None
        new_str = record.text.replace(b'\x03', b'\t').replace(b'\x05', b'\t').replace(b'\x0e', b'\t').replace(b'\x12', b'\t')
        parts = new_str.split(b'\t')
        for part in parts:
            if part.startswith(b'fn='):
                info = part[3:]
                return device, info.decode("utf-8") 
    elif b'MacBook' in record.text:
        device = 'Apple'
        new_str = record.text.replace(b'\x14', b',').replace(b'\x11', b',').replace(b'\x07', b',').replace(b'\x08', b',')
        parts = new_str.split(b',')
        for part in parts:
            if part.startswith(b'model='):
                info = part[6:]
                return device, info.decode("utf-8")
            elif part.startswith(b'am='):
                info = part[3:]
                return device, info.decode("utf-8") 

    # iPads send info in TXT records
    for device_name in apple_devices.keys():
        if device_name in str(record.text):
            device = "Apple"
            info = apple_devices[device_name]
            return device, info

    return record.text, None

def parse_mobdev(mobdev_str):
    parts = mobdev_str.split('.')
    ip_mac, _ = parts[0].split('-')
    mac, ip = ip_mac.split('@')
    return mac, ip, parts[2]
    
def parse_record_types(answer):
    printed = False
    prt_str = ""
    meta = []
    if hasattr(answer, "ttl"):
        meta.append(f"ttl={answer.ttl}")
    if hasattr(answer, "class_"):
        meta.append(f"class={answer.class_}")
    if hasattr(answer, "unique"):
        meta.append(f"unique={answer.unique}")
    meta_str = f" ({', '.join(meta)})" if meta else ""
    if answer.type == 12:
        # PTR
        alias = answer.alias
        for key, value in apple_devices.items():
            if key in alias:
                prt_str = bcolors.WARNING + f'\tThe model of the {key} is {value}{meta_str}' + bcolors.ENDC
                printed = True
        if '_homekit' in alias:
            prt_str = bcolors.WARNING + f'\tThis host knows the Apple Homekit with id: {alias.split(".")[0]}{meta_str}' + bcolors.ENDC
            printed = True
        elif '_companion-link' in alias:
            # Sometimes the companion-link DO have a name of device...
            if '_companion-link' in alias.split('.')[1]:
                instance = alias.split('.')[0]
                prt_str = (
                    bcolors.WARNING
                    + "\tAdvertises Apple Companion Link (often related to AirDrop/AirPlay continuity). "
                    + f"Service instance: {instance}.{meta_str}"
                    + bcolors.ENDC
                )
                printed = True
            # Sometimes the companion-link does not have a name of device...
            elif '_companion-link' in alias.split('.')[0]:
                prt_str = (
                    bcolors.WARNING
                    + "\tAdvertises Apple Companion Link (often related to AirDrop/AirPlay continuity)."
                    + f"{meta_str}"
                    + bcolors.ENDC
                )
                printed = True
            elif 'Elmedia Video Player' in alias and 'airplay' in alias:
                prt_str = f'\tAirplay Enabled in this host.{meta_str}'
                printed = True
            elif 'mobdev' in alias:
                try:
                    mac, ip, proto = parse_mobdev(alias)
                    prt_str = bcolors.WARNING + f'\tThis host has a PTR record to an iTunes WiFi Sync service named {answer.name}, on MAC {mac}, and IP {ip} using protocol {proto}{meta_str}' + bcolors.ENDC
                    printed = True
                except:
                    pass
                            
        if not printed:
            prt_str = f'\tAnswer Type: PTR. Name: {answer.name} Alias: {alias}{meta_str}'
        
    elif answer.type ==5:
        # CNAME
        prt_str = f'\tAnswer Type: CNAME. Name: {answer.name}. Rdata to process: {answer.alias}{meta_str}'
    elif answer.type == 16:
        # TXT type
        # TODO: some handling here
        device, info = parse_txt(answer)
        if info is not None:
            prt_str = f'\tAnswer Type: TXT Device: {device} Info: {info}{meta_str}'
        else:
            prt_str = f'\tAnswer Type: TXT Text: {device}{meta_str}'
    elif answer.type == 1:
        # A
        ip = socket.inet_ntoa(answer.address)
        prt_str = bcolors.WARNING + f'\tThe IPv4 address of this device named {answer.name} is {ip}{meta_str}' + bcolors.ENDC
    elif answer.type == 28:
        # AAAA
        ip = socket.inet_ntop(socket.AF_INET6, answer.address)
        prt_str = bcolors.WARNING + f'\tThe IPv6 address of this device named {answer.name} is {ip}{meta_str}' + bcolors.ENDC                    
    elif answer.type == 13:
        # HINFO
        prt_str = f'\tAnswer Type: HINFO. Name: {answer.name}. OS : {answer.os}, CPU: {answer.cpu}{meta_str}'
    elif answer.type == 47:
        # NSEC
        prt_str = f'\tAnswer Type: NSEC. Name: {answer.name}. Rdtypes: {answer.rdtypes}, Next name: {answer.next_name}{meta_str}'
    elif answer.type == 33:
        # SRV
        prt_str = '\tServices Offered in the Answers:\n'
        prt_str += f"\t\tAnswer Type: SRV. Name: {answer.name} Server: {answer.server} Port: {answer.port} Priority: {answer.priority} Weight: {getattr(answer, 'weight', '?')}{meta_str}"

    return prt_str

def _normalize_hostname(name: str) -> str:
    name = (name or "").strip()
    if name.endswith("."):
        name = name[:-1]
    return name

def _parse_ssdp_payload(payload: bytes):
    """
    Parse SSDP payload (HTTPU). Returns (start_line, headers_dict) or (None, None).
    """
    if not payload:
        return None, None
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None, None
    lines = [ln.strip("\r") for ln in text.split("\n") if ln.strip("\r")]
    if not lines:
        return None, None
    start_line = lines[0].strip()
    headers = {}
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers[k.strip().upper()] = v.strip()
    return start_line, headers

def _parse_txt_kv(text: bytes):
    """
    Best-effort decoding of mDNS TXT RDATA into key/value pairs.
    TXT is a series of length-prefixed strings; zeroconf exposes raw bytes.
    We heuristically split on NUL and common separators.
    """
    if not text:
        return {}
    chunks = []
    if b"\x00" in text:
        chunks = [c for c in text.split(b"\x00") if c]
    else:
        chunks = [text]
    out = {}
    for c in chunks:
        try:
            s = c.decode("utf-8", errors="replace")
        except Exception:
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                out.setdefault(k, set()).add(v)
        else:
            k = s.strip()
            if k:
                out.setdefault(k, set()).add("")
    return out

def _parse_mdns_txt_strings(raw: bytes):
    """
    Parse mDNS TXT RDATA into a list of strings.

    TXT RDATA is one or more <character-string> items:
      - 1 byte length
      - N bytes of content

    zeroconf exposes the concatenated raw bytes; Apple TXT often contains
    non-printable separators, so this makes it readable and structured.
    """
    if not raw:
        return []
    out = []
    i = 0
    n = len(raw)
    while i < n:
        ln = raw[i]
        i += 1
        if ln == 0:
            continue
        if i + ln > n:
            # Malformed/truncated
            chunk = raw[i:]
            i = n
        else:
            chunk = raw[i : i + ln]
            i += ln
        try:
            out.append(chunk.decode("utf-8", errors="replace"))
        except Exception:
            out.append(repr(chunk))
    return out

def _extract_mdns_identity(srcip: str, srcip6: str, records):
    """
    From zeroconf DNS records, infer which hostname is likely the sender itself
    (vs. a sleep proxy) based on whether A/AAAA matches the packet source.
    """
    claimed = set()
    self_hostnames = set()
    proxied_hostnames = set()

    for r in records:
        rtype = getattr(r, "type", None)
        if rtype == 1 and hasattr(r, "address"):
            name = _normalize_hostname(getattr(r, "name", ""))
            ip = socket.inet_ntoa(r.address)
            claimed.add(name)
            if srcip:
                if ip == srcip:
                    self_hostnames.add(name)
                else:
                    proxied_hostnames.add(name)
        elif rtype == 28 and hasattr(r, "address"):
            name = _normalize_hostname(getattr(r, "name", ""))
            ip6 = socket.inet_ntop(socket.AF_INET6, r.address)
            claimed.add(name)
            if srcip6:
                if ip6 == srcip6:
                    self_hostnames.add(name)
                else:
                    proxied_hostnames.add(name)
        elif rtype == 33 and hasattr(r, "server"):
            srv = _normalize_hostname(getattr(r, "server", ""))
            if srv:
                claimed.add(srv)
        elif rtype == 12 and hasattr(r, "alias"):
            alias = _normalize_hostname(getattr(r, "alias", ""))
            if alias.endswith(".local"):
                claimed.add(alias)

    likely_self = None
    if len(self_hostnames) == 1:
        likely_self = next(iter(self_hostnames))
    return likely_self, claimed, proxied_hostnames, self_hostnames

def _extract_mdns_services(records):
    services = set()
    for r in records:
        rtype = getattr(r, "type", None)
        if rtype == 12 and hasattr(r, "name"):
            name = _normalize_hostname(getattr(r, "name", ""))
            if name.endswith(".local") and "._" in name:
                services.add(name)
        elif rtype == 33 and hasattr(r, "name"):
            name = _normalize_hostname(getattr(r, "name", ""))
            if name.endswith(".local") and "._" in name:
                services.add(name)
    return services

def _print_summary():
    if not device_observations:
        print("No devices observed.")
        return

    try:
        print("=== Device Summary ===")
        for mac in sorted(device_observations.keys()):
            obs = device_observations[mac]
            vendor = obs.get("vendor") or "Unknown"
            ips = ", ".join(sorted(obs["ips"])) if obs["ips"] else "-"
            names = ", ".join(sorted(obs["names"])) if obs["names"] else "-"
            mdns_self = ", ".join(sorted(obs["mdns_self_hostnames"])) if obs["mdns_self_hostnames"] else "-"
            mdns_other = ", ".join(sorted(obs["mdns_other_hostnames"])) if obs["mdns_other_hostnames"] else "-"
            llmnr_q = ", ".join(sorted(obs["llmnr_questions"])) if obs["llmnr_questions"] else "-"
            igmp = ", ".join(sorted(obs["igmp_groups"])) if obs["igmp_groups"] else "-"

            first_seen = obs["first_seen"].isoformat(sep=" ", timespec="seconds") if obs["first_seen"] else "-"
            last_seen = obs["last_seen"].isoformat(sep=" ", timespec="seconds") if obs["last_seen"] else "-"

            print(bcolors.HEADER + f"\n🖥️  {mac} ({vendor})" + bcolors.ENDC)
            print(f"\t- ⏱️  First seen: {first_seen}")
            print(f"\t- ⏱️  Last seen:  {last_seen}")
            print(
                "\t- 📦 Packets: "
                f"total={obs['packets_total']} mdns={obs['packets_mdns']} llmnr={obs['packets_llmnr']} ssdp={obs['packets_ssdp']} igmp={obs['packets_igmp']}"
            )
            print(f"\t- 🌐 Source IPs observed: {ips}")
            print(f"\t- 🏷️  Device label names (inferred): {names}")

            if obs["packets_mdns"]:
                print(bcolors.BLUE + "\t- 🧩 mDNS" + bcolors.ENDC)
                print(f"\t  - ❓ Questions seen: {len(obs['mdns_questions'])} (packet qd-sum={obs['mdns_q_count']})")
                print(f"\t  - ✅ Answers seen: A/AAAA count={obs['mdns_a_count']}")
                print(f"\t  - 📨 Packet roles: query={obs['mdns_packets_query']} response={obs['mdns_packets_response']} (mDNS queries can include known-answer records)")
                print(f"\t  - 🧍 Self hostname(s) (A/AAAA matches SrcIP): {mdns_self}")
                print(f"\t  - 🛰️  Other hostnames referenced (proxy/sleep-proxy possible): {mdns_other}")
                if obs["mdns_service_types"]:
                    print("\t  - 🧪 Service types:")
                    for st in sorted(obs["mdns_service_types"]):
                        print(f"\t    - {st}")
                if obs["mdns_service_instances_advertised"] or obs["mdns_service_instances_referenced"]:
                    print("\t  - 📣 Service instances:")
                    if obs["mdns_service_instances_advertised"]:
                        print("\t    - Owned/advertised by this sender (SRV→self):")
                        for inst in sorted(obs["mdns_service_instances_advertised"]):
                            print(f"\t      - {inst}")
                    if obs["mdns_service_instances_referenced"]:
                        print("\t    - Referenced/seen in packets (not proven owned):")
                        for inst in sorted(obs["mdns_service_instances_referenced"]):
                            print(f"\t      - {inst}")
                if obs["mdns_questions"]:
                    print("\t  - ❓ Question names:")
                    for q in sorted(obs["mdns_questions"]):
                        print(f"\t    - {q}")
                if obs["mdns_ptr_service"] or obs["mdns_ptr_reverse"]:
                    print(
                        "\t  - 🔗 PTR mappings (mDNS; PTR is a pointer record used by DNS-SD; may appear in queries as known-answers):"
                    )
                    if obs["mdns_ptr_service"]:
                        print(
                            "\t    - Service type → instance (mDNS DNS-SD; answers “which instances exist for this service type”; seen in: "
                            f"query={len(obs['mdns_ptr_service_q'])} response={len(obs['mdns_ptr_service_r'])}):"
                        )
                        for st, inst in sorted(obs["mdns_ptr_service"]):
                            print(f"\t      - {st} → {inst}")
                    if obs["mdns_ptr_reverse"]:
                        print(
                            "\t    - Reverse name → hostname (mDNS reverse-DNS PTR; maps IP to name; seen in: "
                            f"query={len(obs['mdns_ptr_reverse_q'])} response={len(obs['mdns_ptr_reverse_r'])}):"
                        )
                        for rev, hn in sorted(obs["mdns_ptr_reverse"]):
                            print(f"\t      - {rev} → {hn}")
                if obs["mdns_srv"]:
                    print("\t  - 🧭 SRV endpoints (instance → target:port):")
                    for inst, server, port, priority, weight in sorted(obs["mdns_srv"]):
                        print(f"\t    - {inst} → {server}:{port} (priority={priority} weight={weight})")
                if obs["mdns_a"]:
                    print("\t  - 🧷 A (IPv4) hostnames:")
                    for hn in sorted(obs["mdns_a"].keys()):
                        print(f"\t    - {hn}: {', '.join(sorted(obs['mdns_a'][hn]))}")
                if obs["mdns_aaaa"]:
                    print("\t  - 🧷 AAAA (IPv6) hostnames:")
                    for hn in sorted(obs["mdns_aaaa"].keys()):
                        print(f"\t    - {hn}: {', '.join(sorted(obs['mdns_aaaa'][hn]))}")
                if obs["mdns_txt_strings"] or obs["mdns_txt_kv"]:
                    print("\t  - 🧾 TXT (decoded & interpreted):")
                    for name in sorted(set(list(obs["mdns_txt_kv"].keys()) + list(obs["mdns_txt_strings"].keys()))):
                        fam = _service_family_from_name(name)
                        fam_label = f" [{fam}]" if fam else ""
                        print(bcolors.GREEN + f"\t    - {name}{fam_label}" + bcolors.ENDC)

                        interpreted = obs["mdns_txt_interpreted"].get(name)
                        if interpreted and interpreted.get("known"):
                            for k in sorted(interpreted["known"].keys()):
                                meta = interpreted["known"][k]
                                vstr = ", ".join(meta["values"])
                                meaning = meta["meaning"]
                                print(bcolors.NORMAL + f"\t      - {k}={vstr}  ↳ {meaning}" + bcolors.ENDC)
                        elif name in obs["mdns_txt_kv"]:
                            # Fall back to raw key/values if we don't have a mapping.
                            for k in sorted(obs["mdns_txt_kv"][name].keys()):
                                vs = obs["mdns_txt_kv"][name][k]
                                vstr = ", ".join(sorted(vs)) if vs else ""
                                print(f"\t      - {k}={vstr}")

                        # Show any unknown keys (still relevant for fingerprinting).
                        if interpreted and interpreted.get("unknown"):
                            print("\t      - (unknown/proprietary keys):")
                            for k in sorted(interpreted["unknown"].keys()):
                                vstr = ", ".join(interpreted["unknown"][k])
                                print(f"\t        - {k}={vstr}")

            if obs["ssdp_start_lines"] or obs["ssdp_headers"]:
                print(bcolors.BLUE + "\t- 📺 SSDP/UPnP" + bcolors.ENDC)
                for sl in sorted(obs["ssdp_start_lines"]):
                    print(f"\t  - {sl}")
                for k in sorted(obs["ssdp_headers"].keys()):
                    vals = "; ".join(sorted(obs["ssdp_headers"][k]))
                    print(f"\t  - {k}: {vals}")

            if obs["llmnr_questions"] or obs["llmnr_answers"]:
                print(bcolors.BLUE + "\t- 🧷 LLMNR" + bcolors.ENDC)
                print(f"\t  - ❓ Questions: {llmnr_q}")
                if obs["llmnr_answers"]:
                    print("\t  - ✅ Answers:")
                    for name, typ, rdata in sorted(obs["llmnr_answers"]):
                        print(f"\t    - {name} type={typ} rdata={rdata}")
            if obs["igmp_groups"]:
                print(bcolors.BLUE + "\t- 📡 IGMP" + bcolors.ENDC)
                print(f"\t  - Groups: {igmp}")

            # High-level device fingerprint from known service families.
            prof = obs.get("profile") or {}
            if any(prof.get(k) for k in ("airplay", "raop", "companion_link")):
                print(bcolors.BLUE + "\t- 🧾 Device Profile (from TXT)" + bcolors.ENDC)
                if prof.get("airplay"):
                    ap = prof["airplay"]
                    print("\t  - AirPlay:")
                    for k in sorted(ap.keys()):
                        vals = ", ".join(sorted(ap[k]))
                        meaning = KNOWN_TXT_KEYS["AirPlay"].get(k, "Unknown/proprietary")
                        print(bcolors.NORMAL + f"\t    - {k}: {vals}  ↳ {meaning}" + bcolors.ENDC)
                if prof.get("raop"):
                    ra = prof["raop"]
                    print("\t  - RAOP:")
                    for k in sorted(ra.keys()):
                        vals = ", ".join(sorted(ra[k]))
                        meaning = KNOWN_TXT_KEYS["RAOP"].get(k, "Unknown/proprietary")
                        print(bcolors.NORMAL + f"\t    - {k}: {vals}  ↳ {meaning}" + bcolors.ENDC)
                if prof.get("companion_link"):
                    cl = prof["companion_link"]
                    print("\t  - Companion Link:")
                    for k in sorted(cl.keys()):
                        vals = ", ".join(sorted(cl[k]))
                        meaning = KNOWN_TXT_KEYS["CompanionLink"].get(k, "Unknown/proprietary")
                        print(bcolors.NORMAL + f"\t    - {k}: {vals}  ↳ {meaning}" + bcolors.ENDC)
    except BrokenPipeError:
        # Common when piping to head/tail.
        try:
            import sys

            sys.exit(0)
        except Exception:
            return

def do(pkt):
    """
    Do something
    """
    if Ether not in pkt:
        return

    shw = pkt[Ether].src.upper()
    mac_vendor = macvendor.get_all(shw).manuf_long
    srcip = pkt[IP].src if IP in pkt else ""
    srcip6 = pkt[IPv6].src if IPv6 in pkt else ""

    if UDP in pkt and (srcip or srcip6):
        UDPlayer = pkt[UDP]
        obs = _get_device_obs(shw)
        obs["vendor"] = mac_vendor
        obs["packets_total"] += 1
        ts = datetime.fromtimestamp(float(getattr(pkt, "time", datetime.now().timestamp())))
        obs["first_seen"] = ts if obs["first_seen"] is None else min(obs["first_seen"], ts)
        obs["last_seen"] = ts if obs["last_seen"] is None else max(obs["last_seen"], ts)
        if srcip:
            obs["ips"].add(srcip)
        if srcip6:
            obs["ips"].add(srcip6)

        # mDNS
        if UDPlayer.dport == 5353:
            add_client(shw, srcip or srcip6)
            current_name = get_client(shw)["name"]
            if current_name and "unknown" not in current_name:
                obs["names"].add(current_name)
            obs["packets_mdns"] += 1
            is_response = None
            if DNS in pkt:
                try:
                    is_response = int(pkt[DNS].qr) == 1
                    if is_response:
                        obs["mdns_packets_response"] += 1
                    else:
                        obs["mdns_packets_query"] += 1
                except Exception:
                    pass
            inc_packet = zproto.incoming.DNSIncoming(bytes(UDPlayer.payload), (6 if srcip6 else 4, srcip6 or srcip))

            num_questions = inc_packet.num_questions
            num_additional_records = inc_packet.num_additionals
            num_answers = inc_packet.num_answers
            num_auth = inc_packet.num_authorities
            answers = inc_packet.answers()
            obs["mdns_q_count"] += int(num_questions or 0)
            obs["mdns_a_count"] += int(num_answers or 0) + int(num_auth or 0) + int(num_additional_records or 0)
            for question in inc_packet.questions:
                try:
                    obs["mdns_questions"].add(_normalize_hostname(question.name))
                except Exception:
                    pass
            # Track self hostnames during this packet so we can categorize instance ownership.
            packet_self_hosts = set()
            for r in answers:
                rtype = getattr(r, "type", None)
                if rtype == 12 and hasattr(r, "name") and hasattr(r, "alias"):
                    ptr_name = _normalize_hostname(r.name)
                    ptr_alias = _normalize_hostname(r.alias)
                    if ptr_name.endswith(".in-addr.arpa") or ptr_name.endswith(".ip6.arpa"):
                        obs["mdns_ptr_reverse"].add((ptr_name, ptr_alias))
                        if is_response is True:
                            obs["mdns_ptr_reverse_r"].add((ptr_name, ptr_alias))
                        elif is_response is False:
                            obs["mdns_ptr_reverse_q"].add((ptr_name, ptr_alias))
                    elif ptr_name.startswith("_") and ptr_name.endswith(".local"):
                        # service type -> service instance
                        obs["mdns_ptr_service"].add((ptr_name, ptr_alias))
                        if is_response is True:
                            obs["mdns_ptr_service_r"].add((ptr_name, ptr_alias))
                        elif is_response is False:
                            obs["mdns_ptr_service_q"].add((ptr_name, ptr_alias))
                        obs["mdns_service_types"].add(ptr_name)
                        if "._" in ptr_alias and ptr_alias.endswith(".local"):
                            # Ownership decided after SRV parsing in this packet; add later as referenced.
                            obs["mdns_service_instances_referenced"].add(ptr_alias)
                    else:
                        # Other PTR; still keep as a "question/observed name"
                        obs["mdns_questions"].add(ptr_name)
                elif rtype == 33 and hasattr(r, "name"):
                    obs["mdns_srv"].add(
                        (
                            _normalize_hostname(r.name),
                            _normalize_hostname(getattr(r, "server", "")),
                            int(getattr(r, "port", 0)),
                            int(getattr(r, "priority", 0)),
                            int(getattr(r, "weight", 0)),
                        )
                    )
                    srv_name = _normalize_hostname(getattr(r, "name", ""))
                    if srv_name.startswith("_") and srv_name.endswith(".local"):
                        obs["mdns_service_types"].add(srv_name)
                    if "._" in srv_name and srv_name.endswith(".local"):
                        obs["mdns_service_instances_referenced"].add(srv_name)
                elif rtype == 1 and hasattr(r, "name") and hasattr(r, "address"):
                    hn = _normalize_hostname(r.name)
                    ip = socket.inet_ntoa(r.address)
                    obs["mdns_a"].setdefault(hn, set()).add(ip)
                    if srcip and ip == srcip:
                        packet_self_hosts.add(hn)
                elif rtype == 28 and hasattr(r, "name") and hasattr(r, "address"):
                    hn = _normalize_hostname(r.name)
                    ip6 = socket.inet_ntop(socket.AF_INET6, r.address)
                    obs["mdns_aaaa"].setdefault(hn, set()).add(ip6)
                    if srcip6 and ip6 == srcip6:
                        packet_self_hosts.add(hn)
                elif rtype == 16 and hasattr(r, "name") and hasattr(r, "text"):
                    name = _normalize_hostname(r.name)
                    raw = r.text
                    strings = _parse_mdns_txt_strings(raw)
                    if strings:
                        obs["mdns_txt_strings"].setdefault(name, set()).update(strings)
                        # Parse key/values from the decoded strings (not raw bytes)
                        for s in strings:
                            if "=" in s:
                                k, v = s.split("=", 1)
                                k = k.strip()
                                v = v.strip()
                                if k:
                                    slot = obs["mdns_txt_kv"].setdefault(name, {})
                                    slot.setdefault(k, set()).add(v)
                    else:
                        kv = _parse_txt_kv(raw)
                        if kv:
                            for k, vs in kv.items():
                                slot = obs["mdns_txt_kv"].setdefault(name, {})
                                slot.setdefault(k, set()).update(vs)

                    # Interpret known TXT keys and store in the device profile.
                    if name in obs["mdns_txt_kv"]:
                        interpreted = _interpret_txt(name, obs["mdns_txt_kv"][name])
                        if interpreted:
                            obs["mdns_txt_interpreted"][name] = interpreted
                            fam = interpreted["family"]
                            if fam == "AirPlay":
                                prof = obs["profile"]["airplay"]
                            elif fam == "RAOP":
                                prof = obs["profile"]["raop"]
                            else:
                                prof = obs["profile"]["companion_link"]
                            for kk, meta in interpreted["known"].items():
                                prof.setdefault(kk, set()).update(meta["values"])
                            for kk, values in interpreted["unknown"].items():
                                prof.setdefault(kk, set()).update(values)

            likely_self, claimed_hosts, proxied_hosts, self_hosts = _extract_mdns_identity(srcip, srcip6, answers)
            # Combine per-packet and extracted self hosts.
            packet_self_hosts.update({_normalize_hostname(h) for h in self_hosts if h})
            if likely_self:
                packet_self_hosts.add(_normalize_hostname(likely_self))

            # Re-classify SRV-owned instances as advertised when SRV target points to self.
            for inst, server, port, priority, weight in list(obs["mdns_srv"]):
                if server and server in packet_self_hosts:
                    obs["mdns_service_instances_advertised"].add(inst)
                    if inst in obs["mdns_service_instances_referenced"]:
                        obs["mdns_service_instances_referenced"].discard(inst)

            if likely_self:
                obs["mdns_self_hostnames"].add(_normalize_hostname(likely_self))
            obs["mdns_other_hostnames"].update({_normalize_hostname(h) for h in proxied_hosts if h})
            # Only treat ".local" owner names as hostnames (not service types/instances).
            for h in claimed_hosts:
                h = _normalize_hostname(h)
                if h.endswith(".local") and "._" not in h and not h.startswith("_"):
                    obs["names"].add(h)
            if likely_self and "unknown" in get_client(shw)["name"]:
                # Store a human-friendly name (drop .local suffix)
                nice = likely_self[:-6] if likely_self.endswith(".local") else likely_self
                add_client(shw, srcip or srcip6, nice)
                obs["names"].add(_normalize_hostname(likely_self))

            if not args.summary:
                # TODO: Find the Authoritative Nameservers
                if args.debug:
                    print("[Debug]:", inc_packet)
                ip_label = srcip if srcip else srcip6
                print(
                    bcolors.HEADER
                    + f"\033[36m{datetime.now()}\033[95m | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{ip_label}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m | Questions: \033[36m{num_questions}\033[95m | Additional Records: \033[36m{num_additional_records}\033[95m | Answers: \033[36m{num_answers}\033[95m | Authoritative Nameservers: \033[36m{num_auth}\033[95m"
                    + bcolors.ENDC
                )
                if likely_self:
                    print(bcolors.BLUE + f"\tRecords indicate sender is advertising itself as: {likely_self}" + bcolors.ENDC)
                elif self_hosts:
                    shown = ", ".join(sorted(list(self_hosts))[:6])
                    suffix = " ..." if len(self_hosts) > 6 else ""
                    print(bcolors.BLUE + f"\tMultiple self-matching hostnames in records: {shown}{suffix}" + bcolors.ENDC)
                if proxied_hosts:
                    shown = ", ".join(sorted(list(proxied_hosts))[:6])
                    suffix = " ..." if len(proxied_hosts) > 6 else ""
                    print(bcolors.BLUE + f"\tRecords also reference other hostnames (proxy/reflector/sleep-proxy behavior possible): {shown}{suffix}" + bcolors.ENDC)

                #####################
                # Process the questions
                #
                print(bcolors.HEADER + f' > Questions: \033[36m{num_questions}\033[95m' + bcolors.ENDC)
                for question in inc_packet.questions:
                    if args.debug:
                        print(f"\t[Debug] Question: {question}")
                    else:
                        print(f"\t{question.name}")

                #####################
                # Process all the Records
                #
                print(bcolors.HEADER + f' > Answers + Authorities: \033[36m{num_answers+num_auth}\033[95m' + bcolors.ENDC)
                # The answers hold also the authorities and the additional records
                if len(answers) != (num_answers + num_auth + num_additional_records):
                    print("At least one record was not parsed.")
                if num_answers + num_auth > 0:
                    for answer in answers[: num_answers + num_auth]:
                        if args.debug:
                            print(f"\t[Debug] Record: {answer}")
                        else:
                            print(parse_record_types(answer))

                #####################
                # Process the Additional records
                #
                print(bcolors.HEADER + f' > Additional Records: \033[36m{num_additional_records}\033[95m' + bcolors.ENDC)
                if num_additional_records:
                    for record in answers[num_answers + num_auth :]:
                        if args.debug:
                            print(f"\t[Debug] Record: {record}")
                        else:
                            print(parse_record_types(record))

        # LLMNR (DNS-like)
        elif UDPlayer.dport == 5355:
            add_client(shw, srcip or srcip6)
            obs["packets_llmnr"] += 1
            dns = pkt[DNS] if DNS in pkt else None
            if not dns:
                return
            ip_label = srcip if srcip else srcip6
            if dns.qdcount and dns.qd is not None:
                q = dns.qd
                for _ in range(dns.qdcount):
                    try:
                        qname = _normalize_hostname(q.qname.decode(errors="replace"))
                        obs["llmnr_questions"].add(qname)
                        if not args.summary:
                            pass
                    except Exception:
                        pass
                    q = q.payload
            if dns.ancount and dns.an is not None:
                a = dns.an
                for _ in range(dns.ancount):
                    rrname = _normalize_hostname(getattr(a, "rrname", b"").decode(errors="replace"))
                    rdata = getattr(a, "rdata", None)
                    if rrname:
                        obs["llmnr_answers"].add((rrname, getattr(a, "type", None), str(rdata)))
                    if getattr(a, "type", None) == 1 and isinstance(rdata, str) and rdata == srcip:
                        if "unknown" in get_client(shw)["name"] and rrname:
                            add_client(shw, srcip or srcip6, rrname)
                            obs["names"].add(rrname)
                    a = a.payload
            if not args.summary:
                print(
                    bcolors.HEADER
                    + f"\033[36m{datetime.now()}\033[95m | LLMNR | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{ip_label}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m"
                    + bcolors.ENDC
                )
                if dns.qdcount:
                    print(bcolors.HEADER + f" > Questions: \033[36m{dns.qdcount}\033[95m" + bcolors.ENDC)
                    for qn in sorted(obs["llmnr_questions"]):
                        print(f"\t{qn}")
                if dns.ancount:
                    print(bcolors.HEADER + f" > Answers: \033[36m{dns.ancount}\033[95m" + bcolors.ENDC)
                    for rrname, typ, rdata in sorted(obs["llmnr_answers"]):
                        print(f"\t{rrname} type={typ} rdata={rdata}")

        # SSDP / UPnP
        elif UDPlayer.dport == 1900 or UDPlayer.sport == 1900:
            add_client(shw, srcip or srcip6)
            obs["packets_ssdp"] += 1
            start_line, headers = _parse_ssdp_payload(bytes(UDPlayer.payload))
            if not start_line:
                return
            ip_label = srcip if srcip else srcip6
            obs["ssdp_start_lines"].add(start_line)
            for k, v in headers.items():
                obs["ssdp_headers"].setdefault(k, set()).add(v)
            if not args.summary:
                print(
                    bcolors.HEADER
                    + f"\033[36m{datetime.now()}\033[95m | SSDP | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{ip_label}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m"
                    + bcolors.ENDC
                )
                print(bcolors.HEADER + f" > {start_line}" + bcolors.ENDC)
                for k in ("HOST", "NT", "NTS", "USN", "ST", "LOCATION", "SERVER", "MAN", "MX", "CACHE-CONTROL"):
                    if k in headers:
                        print(f"\t{k}: {headers[k]}")

    # IGMP (multicast group management)
    if IP in pkt and pkt[IP].proto == 2:
        add_client(shw, srcip or srcip6)
        obs = _get_device_obs(shw)
        obs["vendor"] = mac_vendor
        obs["packets_total"] += 1
        obs["packets_igmp"] += 1
        ts = datetime.fromtimestamp(float(getattr(pkt, "time", datetime.now().timestamp())))
        obs["first_seen"] = ts if obs["first_seen"] is None else min(obs["first_seen"], ts)
        obs["last_seen"] = ts if obs["last_seen"] is None else max(obs["last_seen"], ts)
        if srcip:
            obs["ips"].add(srcip)
        igmp = pkt.getlayer("IGMP")
        ip_label = srcip if srcip else srcip6
        if igmp:
            group = getattr(igmp, "gaddr", None) or getattr(igmp, "group", None)
            if group:
                obs["igmp_groups"].add(str(group))
            if not args.summary:
                print(
                    bcolors.HEADER
                    + f"\033[36m{datetime.now()}\033[95m | IGMP | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{ip_label}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m"
                    + bcolors.ENDC
                )
                print(f"\tType={getattr(igmp,'type',None)} Group={group}")
        else:
            if not args.summary:
                print(
                    bcolors.HEADER
                    + f"\033[36m{datetime.now()}\033[95m | IGMP | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{ip_label}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m"
                    + bcolors.ENDC
                )
                print("\t(Unparsed IGMP)")


# Main
####################
if __name__ == '__main__':
    # Avoid BrokenPipeError stack traces when piping output (e.g. to head/tail).
    try:
        import signal

        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    parser = argparse.ArgumentParser()
    parser.add_argument('-v',
                        '--verbose',
                        help='Verbosity level. This shows more info about the results.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-d',
                        '--debug',
                        help='Debugging level. This shows inner information about the flows.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-r',
                        '--readfile',
                        help='Name of the pcap file to read.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-i',
                        '--interface',
                        help='Name of the interface to use.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-f',
                        '--filter',
                        help='Tcpdump style filter to use.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('--summary',
                        help='At end of offline PCAP parsing, print a per-device summary (IPs, names, proxied hostnames, services).',
                        action='store_true',
                        required=False)

    args = parser.parse_args()

    # Reload the file of Mac vendors
    macvendor.refresh()

    if args.interface:
        sniff(iface=args.interface, prn=do, store=0, filter=args.filter)
    elif args.readfile:
        sniff(offline=args.readfile,prn=do,store=0, filter=args.filter)
        if args.summary:
            _print_summary()
