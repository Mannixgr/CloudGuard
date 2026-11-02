"""Run: python -m unittest   (no AWS calls)"""
import unittest
from datetime import date

from scan import tag_findings

TODAY = date(2026, 11, 2)
FULL = [{"Key": k, "Value": "x"} for k in ("Project", "Environment", "Owner", "ManagedBy", "Purpose")]


class TagFindings(unittest.TestCase):
    def test_fully_tagged_is_clean(self):
        self.assertEqual(tag_findings(FULL, TODAY), [])

    def test_untagged_lists_every_required_key(self):
        self.assertEqual(len(tag_findings(None, TODAY)), 5)

    def test_expired(self):
        tags = FULL + [{"Key": "ExpiresOn", "Value": "2026-10-31"}]
        self.assertEqual(tag_findings(tags, TODAY), ["expired on 2026-10-31 (waste)"])

    def test_expires_today_is_not_expired(self):
        tags = FULL + [{"Key": "ExpiresOn", "Value": "2026-11-02"}]
        self.assertEqual(tag_findings(tags, TODAY), [])

    def test_bad_date(self):
        tags = FULL + [{"Key": "ExpiresOn", "Value": "31/10/2026"}]
        self.assertIn("not YYYY-MM-DD", tag_findings(tags, TODAY)[0])


if __name__ == "__main__":
    unittest.main()
