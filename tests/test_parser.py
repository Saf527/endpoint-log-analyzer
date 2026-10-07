import tempfile
import unittest
from pathlib import Path

from analyzer.parser import load_logs


class TestParser(unittest.TestCase):
    def test_load_csv(self):
        content = (
            "timestamp,event_type,username,source_ip,process,command_line,status,message\n"
            "2026-01-01T00:00:00Z,AUTH_FAILURE,test,192.0.2.1,,,,failed\n"
        )

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "logs.csv"
            path.write_text(content, encoding="utf-8")
            events = load_logs(str(path), "csv")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "AUTH_FAILURE")
        self.assertEqual(events[0]["source_ip"], "192.0.2.1")


if __name__ == "__main__":
    unittest.main()
