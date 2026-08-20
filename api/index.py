from typing import Any
import re

from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI(
    title="Release Gate",
    version="1.0.0",
)


REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def release_gate(payload: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    workflow = payload.get("workflow") or {}
    image = payload.get("image") or {}

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------
    permissions = workflow.get("permissions")

    if permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # Pull request trigger
    # ---------------------------------------------------------
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # Tests
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # Actions
    # ---------------------------------------------------------
    actions = workflow.get("actions", [])

    if not isinstance(actions, list):
        actions = []

    for action in actions:
        if not isinstance(action, dict):
            violations.append("MUTABLE_ACTION")
            continue

        owner = action.get("owner")
        action_ref = action.get("ref")

        # GitHub-owned actions may use tags such as v4.
        if owner == "actions":
            continue

        # Every third-party action must use a full lowercase SHA.
        if (
            not isinstance(action_ref, str)
            or not FULL_SHA_RE.fullmatch(action_ref)
        ):
            violations.append("MUTABLE_ACTION")

    # ---------------------------------------------------------
    # Image security
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # Production
    # ---------------------------------------------------------
    if target == "production":

        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving deterministic order.
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


# -------------------------------------------------------------
# Vercel-facing endpoint
#
# Vercel's Python runtime routes /api/* into api/index.py.
# -------------------------------------------------------------
@app.post("/api/release-gate")
async def release_gate_api(payload: dict[str, Any]):
    return JSONResponse(
        status_code=200,
        content=release_gate(payload),
    )


# Also keep the route available when running FastAPI directly.
@app.post("/release-gate")
async def release_gate_direct(payload: dict[str, Any]):
    return JSONResponse(
        status_code=200,
        content=release_gate(payload),
    )


@app.get("/")
async def root():
    return {
        "service": "release-gate",
        "status": "ok",
    }


@app.get("/api")
async def api_root():
    return {
        "service": "release-gate",
        "status": "ok",
    }
