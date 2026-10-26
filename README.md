# CloudGuard

An agentic AWS operations assistant I'm building in phases: read-only scans, then detection rules for cost waste and security misconfigurations, then an AI agent that investigates findings and proposes fixes for human approval.

**Status: early development.** This repo is the start of the project. Items under [Roadmap](#roadmap) are planned unless marked done.

## Why I'm building it

I want hands-on experience with what cloud operations teams actually do: finding waste, catching risky configuration, and working out what happened during an incident. I'm building it in small steps, each one usable on its own, and learning boto3 and AWS tooling as I go.

## Design principles

- **Read-only first.** Every early phase runs under a least-privilege, read-only IAM profile. CloudGuard observes and reports before it is ever allowed to change anything.
- **Test against known-bad infrastructure.** Detection rules are checked against resources I deliberately misconfigure myself, so I know a rule fires for the right reason.
- **Infrastructure as code.** AWS resources are defined in Terraform, not clicked together in the console.
- **Human in the loop.** The agent can read and propose, never apply. Any change to infrastructure goes through explicit approval.

## How it works

![CloudGuard design: read-only scan, detection rules, findings history, AI agent, human approval](https://raw.githubusercontent.com/Mannixgr/mannix-portfolio/main/cloudguard.svg)

Solid boxes exist today, amber dashed is in progress (Phase 0.5) and green dashed is planned. The diagram is maintained in my portfolio repo and embedded here, so one edit updates both.

## Roadmap

| Phase | Goal | Status |
| --- | --- | --- |
| 0 | Seed deliberately misconfigured AWS resources (Terraform) to test detections against | Planned |
| 0.5 | boto3 on-ramp: read-only scripts, starting with `describe_instances()` under a read-only IAM profile | In progress |
| 1 | Detection rules for cost waste and security misconfigurations | Planned |
| 2 | API layer (FastAPI + Postgres) and findings history | Planned |
| 3 | Incident investigation: correlate CloudTrail and CloudWatch data around a finding | Planned |
| v2 | Agentic investigator: an LLM agent calls read-only AWS tools (CloudTrail, CloudWatch, the Phase 1 scans), explains the likely cause and proposes a fix as a Terraform change for human approval | Planned |

## Tech stack

Python · boto3 · LLM agents (tool calling) · FastAPI · PostgreSQL · Terraform · AWS (IAM, EC2, CloudTrail, CloudWatch)

## Getting started

You need Python 3.10+ and an AWS account with a **read-only** profile configured.

```bash
git clone https://github.com/Mannixgr/CloudGuard.git
cd CloudGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Point boto3 at your read-only profile and region (replace the profile name with yours):

```bash
export AWS_PROFILE=<your-readonly-profile>
export AWS_DEFAULT_REGION=ca-central-1
```

Scripts will be added under this repo as each phase lands. Each one documents the IAM permissions it needs.

## Security notes

- Never commit AWS credentials. Use named profiles or short-lived credentials.
- Run everything under a read-only role until a phase explicitly requires more.
- Seeded test resources are intentionally insecure. Create them only in a dedicated sandbox account and destroy them when finished.

## Related

- [enterprise-hybrid-aws](https://github.com/Mannixgr/enterprise-hybrid-aws): the Terraform and GitHub Actions OIDC environment this runs alongside
- [Portfolio](https://portfolio-site.tail8c489d.ts.net/)

## Author

Mannix Graham, Computer Science (Honours) at Wilfrid Laurier University.
[LinkedIn](https://linkedin.com/in/mannixgraham) · [GitHub](https://github.com/Mannixgr)