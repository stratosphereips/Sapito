import io
import unittest
from contextlib import redirect_stdout

from scapy.all import PcapReader
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

import sapito


class TestSapitoMDNS(unittest.TestCase):
    def test_updates_client_name_from_a_record_matching_source_ip(self):
        # Ensure clean state between runs
        sapito.clients.clear()

        buf = io.StringIO()
        with redirect_stdout(buf):
            updated = False
            reader = PcapReader("bsidesprg2026-1.pcap")
            try:
                for p in reader:
                    if UDP in p and IP in p and int(p[UDP].dport) == 5353 and Ether in p:
                        sapito.do(p)
                        shw = p[Ether].src.upper()
                        if shw in sapito.clients and "unknown" not in sapito.clients[shw]["name"]:
                            updated = True
                            break
            finally:
                reader.close()

        self.assertTrue(updated, "Expected at least one mDNS packet to update a client name")

    def test_summary_collects_ips_and_names(self):
        sapito.clients.clear()
        sapito.device_observations.clear()

        buf = io.StringIO()
        reader = PcapReader("bsidesprg2026-1.pcap")
        try:
            with redirect_stdout(buf):
                for p in reader:
                    if UDP in p and IP in p and int(p[UDP].dport) == 5353 and Ether in p:
                        sapito.do(p)
                        # Stop once we have at least one device with a non-empty name set
                        if any(v["names"] for v in sapito.device_observations.values()):
                            break
        finally:
            reader.close()

        self.assertGreater(len(sapito.device_observations), 0)
        mac, obs = next(iter(sapito.device_observations.items()))
        self.assertGreaterEqual(len(obs["ips"]), 1)
        self.assertTrue(any(v["names"] for v in sapito.device_observations.values()))

    def test_interprets_airplay_raop_txt_keys_into_profile(self):
        sapito.clients.clear()
        sapito.device_observations.clear()

        buf = io.StringIO()
        reader = PcapReader("bsidesprg2026-1.pcap")
        try:
            with redirect_stdout(buf):
                for p in reader:
                    if UDP in p and IP in p and int(p[UDP].dport) == 5353 and Ether in p:
                        sapito.do(p)
                        # Stop once any device has interpreted RAOP/AirPlay keys
                        found = False
                        for obs in sapito.device_observations.values():
                            prof = obs.get("profile") or {}
                            if prof.get("raop") or prof.get("airplay") or prof.get("companion_link"):
                                found = True
                                break
                        if found:
                            break
        finally:
            reader.close()

        self.assertTrue(
            any(
                (obs.get("profile") or {}).get("raop") or (obs.get("profile") or {}).get("airplay") or (obs.get("profile") or {}).get("companion_link")
                for obs in sapito.device_observations.values()
            )
        )


if __name__ == "__main__":
    unittest.main()
