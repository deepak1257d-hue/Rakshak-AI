"""Run the workflow against an existing, backend-verified target."""

import argparse
import asyncio
import sys
import uuid
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.database import AsyncSessionLocal
from app.models.domain import TargetAsset, VerificationStatus
from app.workflow.graph import get_workflow_state, run_aegis_workflow


async def run_e2e_demo(target_domain: str) -> int:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(TargetAsset).where(
                TargetAsset.domain == target_domain,
                TargetAsset.verification_status == VerificationStatus.VERIFIED,
            )
        )
        target = result.scalars().first()

    if target is None:
        print(
            f"No verified target named '{target_domain}' exists. Register and verify it through the API first.",
            file=sys.stderr,
        )
        return 1

    scan_id = f"manual-{uuid.uuid4()}"
    result = await run_aegis_workflow(
        target=target.domain,
        target_id=target.id,
        scan_id=scan_id,
        workspace_id=target.workspace_id,
    )
    if "__interrupt__" in result:
        snapshot = get_workflow_state(scan_id)
        if snapshot and snapshot.values:
            result = {**snapshot.values, **result}

    report = result.get("final_report") or {}
    plan = result.get("plan") or {}
    execution = plan.get("execution_summary") or {}

    print(f"Target: {target.domain}")
    print(f"Workflow status: {result.get('status', 'UNKNOWN')}")
    print(f"Tool execution: {execution.get('status', 'NOT_REPORTED')}")
    print(f"Findings: {report.get('total_findings', 0)}")
    print(f"Risk score basis: {report.get('risk_score_basis', 'UNAVAILABLE')}")
    print(f"Maximum scaled CVSS base score: {report.get('max_risk_score', 'Not calculated')}")
    print(f"Average scaled CVSS base score: {report.get('average_risk_score', 'Not calculated')}")

    pending = result.get("__interrupt__")
    if pending:
        print("Patches are awaiting review; workflow-thread decisions cannot authorize dispatch.")
        print("Use the authenticated remediation API to record an approval.")
    if execution.get("failed_count", 0):
        print("One or more scanner tools failed or were unavailable; results may be partial.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AEGIS against a verified target in its database.")
    parser.add_argument("--target", required=True, help="Exact domain of an existing verified target")
    args = parser.parse_args()
    return asyncio.run(run_e2e_demo(args.target))


if __name__ == "__main__":
    raise SystemExit(main())
