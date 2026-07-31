from src.oracle_gold.capability import build_capability_report


def test_capability_report_fails_closed_without_sentinel_and_scope():
    report = build_capability_report(
        tools={
            "aws": True,
            "az": False,
            "gcloud": True,
            "terraform": False,
        },
        authentication={
            "AWS_authenticated": False,
            "AWS_scope_configured": False,
            "AZURE_authenticated": False,
            "AZURE_scope_configured": False,
            "GCP_authenticated": True,
            "GCP_scope_configured": False,
        },
        authorization_sentinel_present=False,
    )

    assert report["any_execution_authorized"] is False
    assert report["ready_platforms"] == []
    assert report["secrets_in_report"] is False
    assert report["credential_values_recorded"] is False
    assert "execution_sentinel_absent" in report["platforms"]["GCP"][
        "blockers"
    ]


def test_capability_requires_every_platform_prerequisite():
    report = build_capability_report(
        tools={
            "aws": True,
            "az": True,
            "gcloud": True,
            "terraform": True,
        },
        authentication={
            "AWS_authenticated": True,
            "AWS_scope_configured": True,
            "AZURE_authenticated": False,
            "AZURE_scope_configured": True,
            "GCP_authenticated": False,
            "GCP_scope_configured": False,
        },
        authorization_sentinel_present=True,
    )

    assert report["ready_platforms"] == ["AWS"]
    assert report["platforms"]["AWS"]["execution_authorized"] is True
    assert report["platforms"]["AZURE"]["execution_authorized"] is False
