const express = require('express');
const app = express();

// Render assigns a dynamic port via process.env.PORT, default to 10000
const PORT = process.env.PORT || 10000;

app.use(express.json());

app.post('/release-gate', (req, res) => {
  try {
    const body = req.body || {};
    const violations = [];

    const target = body.target; 
    const event = body.event;   
    const ref = body.ref;       
    const workflow = body.workflow || {};
    const image = body.image || {};

    // Rule 1: Permissions
    const permissions = workflow.permissions || {};
    const expectedPermissions = { contents: "read", packages: "write", "id-token": "none" };
    const permKeys = Object.keys(permissions);
    const expectedKeys = Object.keys(expectedPermissions);
    
    let hasExcessPermission = false;
    if (permKeys.length !== expectedKeys.length) {
      hasExcessPermission = true;
    } else {
      for (const k of expectedKeys) {
        if (permissions[k] !== expectedPermissions[k]) {
          hasExcessPermission = true;
          break;
        }
      }
    }
    if (hasExcessPermission) {
      violations.push("EXCESS_PERMISSION");
    }

    // Rule 2: Pull request rules
    if (event === "pull_request") {
      if (workflow.trigger !== "pull_request") {
        violations.push("UNSAFE_PR_TRIGGER");
      }
      if (!workflow.testsPassed || !workflow.matrixComplete || workflow.failFast !== false) {
        violations.push("TESTS_INCOMPLETE");
      }
    }

    // Rule 3: Actions pinning rules
    const shaRegex = /^[0-9a-f]{40}$/;
    const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
    for (const act of actions) {
      if (act && act.owner !== "actions") {
        if (!act.ref || !shaRegex.test(act.ref)) {
          if (!violations.includes("MUTABLE_ACTION")) {
            violations.push("MUTABLE_ACTION");
          }
        }
      }
    }

    // Rule 4: Image hardening rules
    if (!image.multiStage) {
      violations.push("SINGLE_STAGE_IMAGE");
    }
    if (image.runsAsRoot) {
      violations.push("ROOT_RUNTIME");
    }
    if (image.secretMode && image.secretMode !== "none" && image.secretMode !== "buildkit") {
      violations.push("SECRET_IN_LAYER");
    }
    if (image.criticalVulnerabilities && image.criticalVulnerabilities > 0) {
      violations.push("CRITICAL_CVE");
    }
    if (!image.digestPinned) {
      violations.push("UNPINNED_IMAGE");
    }

    // Rule 5: Production requirements
    if (target === "production") {
      if (event !== "push" || ref !== "refs/heads/main") {
        violations.push("INVALID_PRODUCTION_REF");
      }
      if (!workflow.environmentApproval) {
        violations.push("APPROVAL_REQUIRED");
      }
    }

    const decision = violations.length === 0 ? "promote" : "block";
    return res.status(200).json({ decision, violations });
  } catch (err) {
    return res.status(200).json({ decision: "block", violations: ["SERVER_ERROR"] });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
