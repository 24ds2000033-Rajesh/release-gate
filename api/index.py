from typing import Any
import re

from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI(
    title="Release Gate",
    version="1.0.0",
)


# Exactly the permissions allowed for a release.
REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

# Third-party actions must use exactly 40 lowercase hexadecimal characters.
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def release_gate(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministically evaluate whether a release may be promoted.

    The returned violation list contains only applicable policy codes.
    """

    violations: list[str] = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    workflow = payload.get("workflow") or {}
    image = payload.get("image") or {}

    # ------------------------------------------------------------
    # 1. LEAST-PRIVILEGE PERMISSIONS
    # ------------------------------------------------------------
    permissions = workflow.get("permissions")

    if permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ------------------------------------------------------------
    # 2. PULL REQUEST SECURITY
    # ------------------------------------------------------------
    #
    # If this is a pull-request event, the workflow itself must use
    # pull_request, never pull_request_target.
    #
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ------------------------------------------------------------
    # 3. TEST COMPLETENESS
    # ------------------------------------------------------------
    #
    # Tests must pass.
    # The complete matrix must finish.
    # failFast must explicitly be false.
    #
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ------------------------------------------------------------
    # 4. ACTION PINNING
    # ------------------------------------------------------------
    actions = workflow.get("actions", [])

    if not isinstance(actions, list):
        actions = []

    for action in actions:
        if not isinstance(action, dict):
            violations.append("MUTABLE_ACTION")
            continue

        owner = action.get("owner")
        action_ref = action.get("ref")

        # Actions owned by "actions" are explicitly allowed to use
        # version tags such as v4.
        if owner == "actions":
            continue

        # Every third-party action must be pinned to a full
        # 40-character lowercase hexadecimal commit SHA.
        if not isinstance(action_ref, str) or not FULL_SHA_RE.fullmatch(
            action_ref
        ):
            violations.append("MUTABLE_ACTION")

    # ------------------------------------------------------------
    # 5. IMAGE HARDENING
    # ------------------------------------------------------------

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")

    # Allowed:
    #   none
    #   buildkit
    #
    # Forbidden:
    #   arg
    #   copy
    #
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ------------------------------------------------------------
    # 6. PRODUCTION RELEASE REQUIREMENTS
    # ------------------------------------------------------------

    if target == "production":

        # Production must be a push to refs/heads/main.
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        # Production also requires explicit environment approval.
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ------------------------------------------------------------
    # Remove duplicate codes while preserving deterministic order.
    # ------------------------------------------------------------
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.post("/release-gate")
async def release_gate_endpoint(payload: dict[str, Any]):
    result = release_gate(payload)

    return JSONResponse(
        status_code=200,
        content=result,
    )


@app.get("/")
async def root():
    return {
        "service": "release-gate",
        "status": "ok",
    }
