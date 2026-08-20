from api.index import release_gate


def base_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/test",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4",
                },
                {
                    "owner": "some-org",
                    "name": "some-action",
                    "ref": "0123456789abcdef0123456789abcdef01234567",
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def test_safe_preview_promotes():
    payload = base_payload()

    result = release_gate(payload)

    assert result == {
        "decision": "promote",
        "violations": [],
    }


def test_excess_permission():
    payload = base_payload()
    payload["workflow"]["permissions"]["issues"] = "write"

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "EXCESS_PERMISSION" in result["violations"]


def test_wrong_permission_value():
    payload = base_payload()
    payload["workflow"]["permissions"]["packages"] = "read"

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "EXCESS_PERMISSION" in result["violations"]


def test_pull_request_target_is_blocked():
    payload = base_payload()
    payload["workflow"]["trigger"] = "pull_request_target"

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in result["violations"]


def test_tests_must_pass():
    payload = base_payload()
    payload["workflow"]["testsPassed"] = False

    result = release_gate(payload)

    assert "TESTS_INCOMPLETE" in result["violations"]


def test_matrix_must_be_complete():
    payload = base_payload()
    payload["workflow"]["matrixComplete"] = False

    result = release_gate(payload)

    assert "TESTS_INCOMPLETE" in result["violations"]


def test_fail_fast_must_be_false():
    payload = base_payload()
    payload["workflow"]["failFast"] = True

    result = release_gate(payload)

    assert "TESTS_INCOMPLETE" in result["violations"]


def test_actions_owned_by_actions_can_use_tag():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {
            "owner": "actions",
            "name": "checkout",
            "ref": "v4",
        }
    ]

    result = release_gate(payload)

    assert "MUTABLE_ACTION" not in result["violations"]


def test_third_party_tag_is_blocked():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {
            "owner": "third-party",
            "name": "example",
            "ref": "v1",
        }
    ]

    result = release_gate(payload)

    assert "MUTABLE_ACTION" in result["violations"]


def test_third_party_short_sha_is_blocked():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {
            "owner": "third-party",
            "name": "example",
            "ref": "0123456789abcdef",
        }
    ]

    result = release_gate(payload)

    assert "MUTABLE_ACTION" in result["violations"]


def test_third_party_uppercase_sha_is_blocked():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {
            "owner": "third-party",
            "name": "example",
            "ref": "0123456789ABCDEF0123456789abcdef01234567",
        }
    ]

    result = release_gate(payload)

    assert "MUTABLE_ACTION" in result["violations"]


def test_third_party_full_lowercase_sha_is_allowed():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {
            "owner": "third-party",
            "name": "example",
            "ref": "0123456789abcdef0123456789abcdef01234567",
        }
    ]

    result = release_gate(payload)

    assert "MUTABLE_ACTION" not in result["violations"]


def test_single_stage_image():
    payload = base_payload()
    payload["image"]["multiStage"] = False

    result = release_gate(payload)

    assert "SINGLE_STAGE_IMAGE" in result["violations"]


def test_root_runtime():
    payload = base_payload()
    payload["image"]["runsAsRoot"] = True

    result = release_gate(payload)

    assert "ROOT_RUNTIME" in result["violations"]


def test_arg_secret_is_blocked():
    payload = base_payload()
    payload["image"]["secretMode"] = "arg"

    result = release_gate(payload)

    assert "SECRET_IN_LAYER" in result["violations"]


def test_copy_secret_is_blocked():
    payload = base_payload()
    payload["image"]["secretMode"] = "copy"

    result = release_gate(payload)

    assert "SECRET_IN_LAYER" in result["violations"]


def test_buildkit_secret_is_allowed():
    payload = base_payload()
    payload["image"]["secretMode"] = "buildkit"

    result = release_gate(payload)

    assert "SECRET_IN_LAYER" not in result["violations"]


def test_critical_cve():
    payload = base_payload()
    payload["image"]["criticalVulnerabilities"] = 1

    result = release_gate(payload)

    assert "CRITICAL_CVE" in result["violations"]


def test_digest_required():
    payload = base_payload()
    payload["image"]["digestPinned"] = False

    result = release_gate(payload)

    assert "UNPINNED_IMAGE" in result["violations"]


def test_safe_production():
    payload = base_payload()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True

    result = release_gate(payload)

    assert result == {
        "decision": "promote",
        "violations": [],
    }


def test_production_wrong_ref():
    payload = base_payload()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/develop"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in result["violations"]


def test_production_pull_request_is_invalid():
    payload = base_payload()

    payload["target"] = "production"
    payload["event"] = "pull_request"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "pull_request"
    payload["workflow"]["environmentApproval"] = True

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in result["violations"]


def test_production_requires_approval():
    payload = base_payload()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = False

    result = release_gate(payload)

    assert result["decision"] == "block"
    assert "APPROVAL_REQUIRED" in result["violations"]


def test_multiple_failures():
    payload = base_payload()

    payload["workflow"]["permissions"]["admin"] = "write"
    payload["workflow"]["trigger"] = "pull_request_target"
    payload["workflow"]["testsPassed"] = False
    payload["workflow"]["matrixComplete"] = False
    payload["workflow"]["failFast"] = True

    payload["workflow"]["actions"] = [
        {
            "owner": "third-party",
            "name": "bad-action",
            "ref": "v1",
        }
    ]

    payload["image"]["multiStage"] = False
    payload["image"]["runsAsRoot"] = True
    payload["image"]["secretMode"] = "copy"
    payload["image"]["criticalVulnerabilities"] = 3
    payload["image"]["digestPinned"] = False

    result = release_gate(payload)

    assert result["decision"] == "block"

    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }

    assert set(result["violations"]) == expected
