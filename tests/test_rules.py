import unittest

from analyzer.rules import (
    detect_auth_bruteforce,
    detect_powershell,
    detect_process_patterns,
)


class TestRules(unittest.TestCase):
    def test_bruteforce_detection(self):
        events = [
            {
                "timestamp": "",
                "event_type": "AUTH_FAILURE",
                "username": "admin",
                "source_ip": "203.0.113.50",
                "process": "",
                "command_line": "",
                "status": "FAILURE",
                "message": "",
            }
            for _ in range(5)
        ]

        findings = detect_auth_bruteforce(events)
        self.assertTrue(any(f["rule_id"] == "AUTH-BRUTE-001" for f in findings))

    def test_encoded_powershell_detection(self):
        event = {
            "timestamp": "",
            "event_type": "PROCESS_START",
            "username": "user",
            "source_ip": "192.0.2.10",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand AAAA",
            "status": "",
            "message": "",
        }

        findings = detect_powershell([event])
        self.assertEqual(findings[0]["rule_id"], "PS-ENC-001")

    def test_suspicious_process_detection(self):
        event = {
            "timestamp": "",
            "event_type": "PROCESS_START",
            "username": "user",
            "source_ip": "192.0.2.10",
            "process": "certutil.exe",
            "command_line": "certutil.exe -urlcache",
            "status": "",
            "message": "",
        }

        findings = detect_process_patterns([event])
        self.assertEqual(findings[0]["rule_id"], "PROC-001")


if __name__ == "__main__":
    unittest.main()
