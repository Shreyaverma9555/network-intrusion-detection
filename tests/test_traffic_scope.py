from __future__ import annotations

import unittest

import pandas as pd

from src.nid.traffic_scope import classify_flow, window_scope


class TrafficScopeTests(unittest.TestCase):
    def test_flow_scopes(self) -> None:
        self.assertEqual(classify_flow("127.0.0.1", "127.0.0.1"), "Host-Local")
        self.assertEqual(classify_flow("192.168.1.10", "192.168.1.20"), "Local LAN")
        self.assertEqual(classify_flow("192.168.1.10", "8.8.8.8"), "Outbound")
        self.assertEqual(classify_flow("8.8.8.8", "192.168.1.10"), "Inbound")
        self.assertEqual(classify_flow("8.8.8.8", "1.1.1.1"), "External")
        self.assertEqual(classify_flow("192.168.1.10", "224.0.0.251"), "Multicast/Broadcast")
        self.assertEqual(classify_flow("", ""), "Unknown")

    def test_window_scope_returns_dominant_scope_and_rates(self) -> None:
        frame = pd.DataFrame(
            {
                "ip.src": ["192.168.1.10", "192.168.1.10", "8.8.8.8"],
                "ip.dst": ["192.168.1.20", "192.168.1.20", "192.168.1.10"],
            }
        )

        scope, rates = window_scope(frame)

        self.assertEqual(scope, "Local LAN")
        self.assertAlmostEqual(rates["local_lan_traffic_rate"], 2 / 3, places=4)
        self.assertAlmostEqual(rates["inbound_traffic_rate"], 1 / 3, places=4)

    def test_same_source_destination_is_counted(self) -> None:
        frame = pd.DataFrame(
            {
                "ip.src": ["192.168.1.10", "192.168.1.10", "192.168.1.20"],
                "ip.dst": ["192.168.1.10", "192.168.1.20", "192.168.1.20"],
            }
        )

        _, rates = window_scope(frame)

        self.assertEqual(rates["same_endpoint_packet_count"], 2)
        self.assertAlmostEqual(rates["same_endpoint_traffic_rate"], 2 / 3, places=4)
        self.assertIn("192.168.1.10", rates["same_endpoint_addresses"])
        self.assertIn("192.168.1.20", rates["same_endpoint_addresses"])


if __name__ == "__main__":
    unittest.main()
