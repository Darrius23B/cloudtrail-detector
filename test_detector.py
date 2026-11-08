import unittest
from detector import (detect_root_usage, detect_failed_login,
                      detect_access_key_created, detect_failed_login_then_key)

def make(name, ip="198.51.100.7", time="2026-10-01T03:00:00Z", outcome=None):
    e = {"eventName": name, "sourceIPAddress": ip, "eventTime": time}
    if outcome:
        e["responseElements"] = {"ConsoleLogin": outcome}
    return e

class TestSingleEventRules(unittest.TestCase):
    def test_root_flags_root(self):
        self.assertEqual(detect_root_usage({"userIdentity": {"type": "Root"}})["severity"], "HIGH")

    def test_root_ignores_iam_user(self):
        self.assertIsNone(detect_root_usage({"userIdentity": {"type": "IAMUser"}}))

    def test_failed_login_flags_failure(self):
        self.assertIsNotNone(detect_failed_login(make("ConsoleLogin", outcome="Failure")))

    def test_failed_login_ignores_success(self):
        self.assertIsNone(detect_failed_login(make("ConsoleLogin", outcome="Success")))

    def test_failed_login_handles_null_response(self):
        event = {"eventName": "ConsoleLogin", "responseElements": None}
        self.assertIsNone(detect_failed_login(event))

    def test_key_flags_create_access_key(self):
        self.assertIsNotNone(detect_access_key_created(make("CreateAccessKey")))

    def test_key_ignores_other_events(self):
        self.assertIsNone(detect_access_key_created(make("ListUsers")))

class TestFailedLoginThenKey(unittest.TestCase):
    def test_flags_key_within_an_hour(self):
        events = [make("ConsoleLogin", time="2026-10-01T03:00:00Z", outcome="Failure"),
                  make("CreateAccessKey", time="2026-10-01T03:45:00Z")]
        self.assertEqual(len(detect_failed_login_then_key(events)), 1)

    def test_ignores_gap_over_an_hour(self):
        events = [make("ConsoleLogin", time="2026-10-01T03:00:00Z", outcome="Failure"),
                  make("CreateAccessKey", time="2026-10-01T06:00:00Z")]
        self.assertEqual(detect_failed_login_then_key(events), [])

    def test_ignores_different_ip(self):
        events = [make("ConsoleLogin", ip="198.51.100.7", outcome="Failure"),
                  make("CreateAccessKey", ip="203.0.113.9", time="2026-10-01T03:10:00Z")]
        self.assertEqual(detect_failed_login_then_key(events), [])

    def test_ignores_key_created_before_failure(self):
        events = [make("CreateAccessKey", time="2026-10-01T03:00:00Z"),
                  make("ConsoleLogin", time="2026-10-01T03:10:00Z", outcome="Failure")]
        self.assertEqual(detect_failed_login_then_key(events), [])

if __name__ == "__main__":
    unittest.main()