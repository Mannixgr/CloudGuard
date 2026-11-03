# CloudGuard B2: First Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Phase 0.5 scanner so it flags every tag that breaks the standard on EC2 instances, NAT gateways, VPN connections and Elastic IPs, prove it against the real account, and commit it locally.

**Architecture:** One script, `scan.py`, with two pure-ish parts: `tag_findings(tags, today)` (rules, no AWS) and `resources(ec2)` (Describe calls, yields `(type, id, tags)`). `main()` joins them under the `cloudguard-readonly` profile. Tests use `unittest` and botocore's `Stubber` (already installed with boto3), so they never call AWS.

**Tech Stack:** Python 3.14 (`.venv`), boto3 ~1.43.118, stdlib `unittest`, `botocore.stub.Stubber`.

**Spec:** `enterprise-hybrid-aws-/docs/tagging.md` (the tag rules) and the B2 line in `cloudguard/CLAUDE.md` ("paginated describes for EC2/NAT/VPN/EIP, flag missing standard tags").

**Starting point (already on branch `feat/first-scanner`, uncommitted):** `scan.py` checks the 5 required keys and `ExpiresOn` dates; `test_scan.py` has 5 passing tests. This plan adds what that version misses.

## Global Constraints

- **Do not push.** Commits stay local on `feat/first-scanner`. Mannix pushes and opens the PR himself.
- Read-only: only `Describe*` calls. Never call anything that creates, modifies or deletes.
- Always `boto3.Session(profile_name="cloudguard-readonly")`; never the `[default]` (admin) profile.
- No new dependencies. `requirements.txt` stays `boto3~=1.43.118`.
- Required keys: `Project`, `Environment`, `Owner`, `ManagedBy`, `Purpose`. Keys are case-sensitive.
- Allowed values (copied verbatim from `tagging.md`): Project `enterprise-hybrid-aws`; Environment `dev`, `bootstrap`, `prod`; Owner `Mannix`; ManagedBy `terraform`, `manual`; Purpose `network`, `cicd`, `waste-lab`; ExpiresOn `YYYY-MM-DD`.
- `ExpiresOn` is optional, but required when `Purpose` is `waste-lab`. A date before today is waste; today itself is not.
- Scan output can hold account IDs and ARNs: print to the terminal only, never commit it (`output/` and `*.log` are gitignored).

## Review Focus

1. **NAT gateway in `failed` state.** It isn't billed and disappears within about an hour, so it must not be reported. Today it is reported (shown with a Stubber check on 2026-11-02). Test: `test_failed_nat_is_skipped` (Task 2).
2. **Lowercase or wrong-case value, e.g. `Environment=Dev`.** Cost Explorer counts it as a separate environment, so it is a finding. Test: `test_wrong_case_value` (Task 1).
3. **Results on page two.** Instances after the first page must not be dropped. Test: `test_instances_follow_next_token` (Task 2).
4. **Empty tag value (`Purpose=""`).** The key exists but the value is not allowed, so it is a finding, not clean. Test: `test_empty_value_is_not_allowed` (Task 1).
5. **`waste-lab` without `ExpiresOn`.** It breaks rule 1 of the standard and is exactly what Phase 0 seeds. Test: `test_waste_lab_needs_expiry` (Task 1).

---

### Task 1: Allowed-value rules in `tag_findings`

**Files:**
- Modify: `scan.py` (constants and `tag_findings`)
- Test: `test_scan.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ALLOWED_VALUES: dict[str, tuple[str, ...]]` in `scan.py`; `tag_findings(tags: list[dict] | None, today: date) -> list[str]` (signature unchanged). Problem string formats: `"missing tag {Key}"`, `"{Key}='{value}' not allowed"`, `"waste-lab needs ExpiresOn"`, plus the two existing ExpiresOn strings.

- [ ] **Step 1: Write the failing tests.** In `test_scan.py`, change `FULL` to valid values: `Project=enterprise-hybrid-aws, Environment=dev, Owner=Mannix, ManagedBy=terraform, Purpose=network`. Add:

```python
def test_wrong_case_value(self):
    tags = [t if t["Key"] != "Environment" else {"Key": "Environment", "Value": "Dev"} for t in FULL]
    self.assertEqual(tag_findings(tags, TODAY), ["Environment='Dev' not allowed"])

def test_empty_value_is_not_allowed(self):
    tags = [t if t["Key"] != "Purpose" else {"Key": "Purpose", "Value": ""} for t in FULL]
    self.assertEqual(tag_findings(tags, TODAY), ["Purpose='' not allowed"])

def test_waste_lab_needs_expiry(self):
    tags = [t if t["Key"] != "Purpose" else {"Key": "Purpose", "Value": "waste-lab"} for t in FULL]
    self.assertEqual(tag_findings(tags, TODAY), ["waste-lab needs ExpiresOn"])
    dated = tags + [{"Key": "ExpiresOn", "Value": "2026-12-01"}]
    self.assertEqual(tag_findings(dated, TODAY), [])
```

- [ ] **Step 2: Run them and check they fail.** `.venv/bin/python -m unittest -v`. Expected: the 3 new tests FAIL (each returns `[]`); the 5 old tests still PASS.

- [ ] **Step 3: Implement.** Add `ALLOWED_VALUES` with the values from Global Constraints and a one-line comment `# copied from enterprise-hybrid-aws-/docs/tagging.md; change that doc first`. Derive `REQUIRED_TAGS` from its keys so the two cannot drift. In `tag_findings`, after the missing-key check, add one problem per present key whose value is not in its tuple, then the waste-lab rule. Keep the order: missing, not allowed, waste-lab, ExpiresOn.

- [ ] **Step 4: Run the tests and check they pass.** `.venv/bin/python -m unittest -v`. Expected: 8 tests, OK.

- [ ] **Step 5: Commit (local only).**

```bash
git add scan.py test_scan.py
git commit -m "feat: flag tag values outside the tagging standard"
```

### Task 2: Test `resources()` with Stubber; skip failed NAT gateways

**Files:**
- Modify: `scan.py` (`resources`, NAT state filter)
- Test: `test_scan.py` (new class `Resources`)

**Interfaces:**
- Consumes: `resources(ec2) -> Iterator[tuple[str, str, list[dict] | None]]` as it stands; type strings `ec2-instance`, `nat-gateway`, `vpn-connection`, `elastic-ip`.
- Produces: same interface; NAT gateways in `deleted`, `deleting` or `failed` are skipped.

- [ ] **Step 1: Write the failing tests.** Build the client with fake credentials so nothing can reach AWS: `boto3.client("ec2", region_name="ca-central-1", aws_access_key_id="x", aws_secret_access_key="x")`, wrap it in `Stubber`, add responses in call order (`describe_instances`, `describe_nat_gateways`, `describe_vpn_connections`, `describe_addresses`), and finish each test with `stubber.assert_no_pending_responses()`. Use a `setUp` helper that stubs the three calls a test doesn't care about with empty lists.

```python
def test_instances_follow_next_token(self):
    # page 1 returns NextToken "t" with i-1 running; page 2 has i-2 running
    self.assertEqual([r[1] for r in self.run_scan()], ["i-1", "i-2"])

def test_terminated_instance_is_skipped(self):
    # one instance, State.Name "terminated"
    self.assertEqual(list(self.run_scan()), [])

def test_failed_nat_is_skipped(self):
    # NAT gateways nat-1 "available", nat-2 "failed", nat-3 "deleted"
    self.assertEqual([r[1] for r in self.run_scan()], ["nat-1"])

def test_deleted_vpn_is_skipped(self):
    # vpn-1 "available", vpn-2 "deleted"; VpnConnections need Type "ipsec.1", CustomerGatewayId, State
    self.assertEqual([r[1] for r in self.run_scan()], ["vpn-1"])

def test_eip_tags_pass_through(self):
    # eipalloc-1 with Tags [{"Key": "Owner", "Value": "Mannix"}]
    self.assertEqual(list(self.run_scan()), [("elastic-ip", "eipalloc-1", [{"Key": "Owner", "Value": "Mannix"}])])
```

- [ ] **Step 2: Run and check.** `.venv/bin/python -m unittest -v`. Expected: `test_failed_nat_is_skipped` FAILS (returns `["nat-1", "nat-2"]`); the other four PASS. They already pass because they pin behaviour the current code has.

- [ ] **Step 3: Implement.** Add `"failed"` to the NAT state tuple in `resources`.

- [ ] **Step 4: Run all tests.** `.venv/bin/python -m unittest -v`. Expected: 13 tests, OK.

- [ ] **Step 5: Commit (local only).**

```bash
git add scan.py test_scan.py
git commit -m "fix: skip failed NAT gateways; test the describe calls with Stubber"
```

### Task 3: Live run against the real account (Mannix runs it)

**Files:**
- Modify: `cloudguard/CLAUDE.md` (Current status; gitignored, not committed)

**Interfaces:**
- Consumes: `python scan.py` from Tasks 1 and 2.
- Produces: nothing in code. The output proves the role, MFA and Describe permissions work.

- [ ] **Step 1: Check the profile.** `aws configure get role_arn --profile cloudguard-readonly`. Expected: the `cloudguard-readonly` role ARN. Do not paste it into chat or files (it holds the account ID).

- [ ] **Step 2: Run it.** `python scan.py` and enter the iPhone MFA code. Expected with dev torn down: no traceback, a last line like `0 resources scanned, 0 with tag findings`. Any line above it is a real finding to read.

- [ ] **Step 3: If it fails.** `AccessDenied` on a Describe call means the role is missing that action (check `SecurityAudit` covers it with `aws iam simulate-principal-policy`, the method from D-37). An MFA or `AssumeRole` error means a profile or code problem, not the script. Fix before Step 4.

- [ ] **Step 4 (optional, costs money): Prove it on real resources.** Only if Mannix chooses to bring dev up through the pipeline (about USD 2.40/day). Run it again and expect the NAT gateway, VPN connection and EIP with no tag findings, because they get `default_tags` plus `Purpose=network`. A finding there is a real tagging bug in `enterprise-hybrid-aws`. Tear dev down afterwards.

- [ ] **Step 5: Final check before handing over.** `git status`: only expected files, no output or logs. `git log --oneline main..` shows the commits from Tasks 1 and 2 (plus the initial `scan.py`/`test_scan.py` commit if it hasn't been made yet). Update the Current status in `cloudguard/CLAUDE.md`. **Do not push.**

## Out of scope (named so nobody adds them)

- JSON or file output, exit codes for CI, other services (S3, IAM, VGW, customer gateways), Cost Explorer (no `ce:` permission yet).
- README roadmap tick and solid boxes in `mannix-portfolio/cloudguard.svg`: do them in the PR step after Mannix pushes.
- The open question about sealed-tracker tags (`Project=sealed-tracker` is outside the allowed values). This scanner doesn't scan S3 or IAM, so it doesn't hit them yet. Resolve it before adding S3.
