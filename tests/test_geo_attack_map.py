from __future__ import annotations

import json
import unittest

import pandas as pd

from src.nid.visualization import attack_map_figure, geo_attack_table


class GeoAttackMapTests(unittest.TestCase):
    def test_geo_attack_table_and_map_use_event_coordinates(self) -> None:
        history = pd.DataFrame(
            [
                {
                    "source_ip": "198.51.100.44",
                    "source_country": "India",
                    "category": "SYN Flood",
                    "severity": "High",
                    "threat_score": 85,
                    "predicted_attack": 1,
                    "statistics": json.dumps({"source_latitude": 20.5937, "source_longitude": 78.9629}),
                },
                {
                    "source_ip": "203.0.113.66",
                    "source_country": "United States",
                    "category": "Port Scan",
                    "severity": "Critical",
                    "threat_score": 92,
                    "predicted_attack": 1,
                    "statistics": json.dumps({"source_latitude": 37.0902, "source_longitude": -95.7129}),
                },
            ]
        )
        history["statistics_parsed"] = history["statistics"].map(json.loads)

        table = geo_attack_table(history)
        figure = attack_map_figure(history)

        self.assertEqual(int(table["Attacks"].sum()), 2)
        self.assertIn("India", set(table["Country"]))
        self.assertGreater(len(figure.data), 0)


if __name__ == "__main__":
    unittest.main()
