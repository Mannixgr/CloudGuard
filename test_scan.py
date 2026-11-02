"""Run: python -m unittest   (no AWS calls)"""
import unittest
from datetime import date

import boto3
from botocore.stub import Stubber

from scan import resources, tag_findings

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


class Resources(unittest.TestCase):
    """Stubber answers the Describe calls in order, so nothing reaches AWS."""

    def run_scan(self, instances=({"Reservations": []},), nats=(), vpns=(), eips=()):
        # Fake credentials: if a call ever escaped the stub, AWS would reject it.
        ec2 = boto3.client("ec2", region_name="ca-central-1",
                           aws_access_key_id="x", aws_secret_access_key="x")
        stub = Stubber(ec2)
        for page in instances:
            stub.add_response("describe_instances", page)
        stub.add_response("describe_nat_gateways", {"NatGateways": list(nats)})
        stub.add_response("describe_vpn_connections", {"VpnConnections": list(vpns)})
        stub.add_response("describe_addresses", {"Addresses": list(eips)})
        with stub:
            found = list(resources(ec2))
        stub.assert_no_pending_responses()
        return found

    @staticmethod
    def instance(iid, state="running"):
        return {"Instances": [{"InstanceId": iid, "State": {"Name": state}}]}

    def test_instances_follow_next_token(self):
        pages = ({"Reservations": [self.instance("i-1")], "NextToken": "t"},
                 {"Reservations": [self.instance("i-2")]})
        self.assertEqual([r[1] for r in self.run_scan(instances=pages)], ["i-1", "i-2"])

    def test_terminated_instance_is_skipped(self):
        pages = ({"Reservations": [self.instance("i-1", "terminated")]},)
        self.assertEqual(self.run_scan(instances=pages), [])

    def test_failed_nat_is_skipped(self):
        nats = [{"NatGatewayId": f"nat-{n}", "State": s}
                for n, s in ((1, "available"), (2, "failed"), (3, "deleted"))]
        self.assertEqual([r[1] for r in self.run_scan(nats=nats)], ["nat-1"])

    def test_deleted_vpn_is_skipped(self):
        vpns = [{"VpnConnectionId": f"vpn-{n}", "State": s, "Type": "ipsec.1", "CustomerGatewayId": "cgw-1"}
                for n, s in ((1, "available"), (2, "deleted"))]
        self.assertEqual([r[1] for r in self.run_scan(vpns=vpns)], ["vpn-1"])

    def test_eip_tags_pass_through(self):
        tags = [{"Key": "Owner", "Value": "Mannix"}]
        eips = [{"AllocationId": "eipalloc-1", "Tags": tags}]
        self.assertEqual(self.run_scan(eips=eips), [("elastic-ip", "eipalloc-1", tags)])


if __name__ == "__main__":
    unittest.main()
