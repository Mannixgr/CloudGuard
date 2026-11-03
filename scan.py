"""Phase 0.5 scanner: list EC2 instances, NAT gateways, VPN connections and
Elastic IPs, and flag any that break the tagging standard
(enterprise-hybrid-aws/docs/tagging.md). Read-only: only Describe* calls.

Run: python scan.py   (asks for the MFA code of the cloudguard-readonly profile)
"""
from datetime import date

import boto3

PROFILE = "cloudguard-readonly"  # never the admin [default] profile
# copied from enterprise-hybrid-aws-/docs/tagging.md; change that doc first
ALLOWED_VALUES = {
    "Project": ("enterprise-hybrid-aws",),
    "Environment": ("dev", "bootstrap", "prod"),
    "Owner": ("Mannix",),
    "ManagedBy": ("terraform", "manual"),
    "Purpose": ("network", "cicd", "waste-lab"),
}
REQUIRED_TAGS = tuple(ALLOWED_VALUES)


def tag_findings(tags, today):
    """Return a list of problems for one resource's tag list ([{"Key":..., "Value":...}])."""
    tags = {t["Key"]: t["Value"] for t in tags or []}
    problems = [f"missing tag {k}" for k in REQUIRED_TAGS if k not in tags]
    problems += [f"{k}='{tags[k]}' not allowed" for k, allowed in ALLOWED_VALUES.items()
                 if k in tags and tags[k] not in allowed]
    expires = tags.get("ExpiresOn")
    if tags.get("Purpose") == "waste-lab" and not expires:
        problems.append("waste-lab needs ExpiresOn")
    if expires:
        try:
            if date.fromisoformat(expires) < today:
                problems.append(f"expired on {expires} (waste)")
        except ValueError:
            problems.append(f"ExpiresOn '{expires}' is not YYYY-MM-DD")
    return problems


def resources(ec2):
    """Yield (type, id, tags) for every live resource we scan."""
    # Paginators follow NextToken for us, so large accounts are not cut off at one page.
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page["Reservations"]:
            for i in reservation["Instances"]:
                if i["State"]["Name"] != "terminated":
                    yield "ec2-instance", i["InstanceId"], i.get("Tags")
    for page in ec2.get_paginator("describe_nat_gateways").paginate():
        for n in page["NatGateways"]:
            if n["State"] not in ("deleted", "deleting", "failed"):  # failed NATs aren't billed
                yield "nat-gateway", n["NatGatewayId"], n.get("Tags")
    # These two have no paginator: AWS returns every item in one response.
    for v in ec2.describe_vpn_connections()["VpnConnections"]:
        if v["State"] not in ("deleted", "deleting"):
            yield "vpn-connection", v["VpnConnectionId"], v.get("Tags")
    for a in ec2.describe_addresses()["Addresses"]:
        yield "elastic-ip", a["AllocationId"], a.get("Tags")


def main():
    ec2 = boto3.Session(profile_name=PROFILE).client("ec2")
    today = date.today()
    scanned = flagged = 0
    for kind, rid, tags in resources(ec2):
        scanned += 1
        problems = tag_findings(tags, today)
        if problems:
            flagged += 1
            print(f"{kind:15} {rid:25} {'; '.join(problems)}")
    print(f"\n{scanned} resources scanned, {flagged} with tag findings")


if __name__ == "__main__":
    main()
