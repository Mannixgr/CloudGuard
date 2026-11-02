"""Run: python -m unittest   (no AWS calls)"""
import unittest
from datetime import date

from scan import tag_findings

TODAY = date(2026, 11, 2)
VALID = {"Project": "enterprise-hybrid-aws", "Environment": "dev", "Owner": "Mannix",
         "ManagedBy": "terraform", "Purpose": "network"}
FULL = [{"Key": k, "Value": v} for k, v in VALID.items()]


def with_tag(key, value):
    return [t if t["Key"] != key else {"Key": key, "Value": value} for t in FULL]


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

    def test_wrong_case_value(self):
        self.assertEqual(tag_findings(with_tag("Environment", "Dev"), TODAY),
                         ["Environment='Dev' not allowed"])

    def test_empty_value_is_not_allowed(self):
        self.assertEqual(tag_findings(with_tag("Purpose", ""), TODAY), ["Purpose='' not allowed"])

    def test_waste_lab_needs_expiry(self):
        tags = with_tag("Purpose", "waste-lab")
        self.assertEqual(tag_findings(tags, TODAY), ["waste-lab needs ExpiresOn"])
        dated = tags + [{"Key": "ExpiresOn", "Value": "2026-12-01"}]
        self.assertEqual(tag_findings(dated, TODAY), [])


if __name__ == "__main__":
    unittest.main()
