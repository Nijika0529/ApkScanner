from __future__ import annotations

from apkscanner.mobsf import MobSFAdapter


def test_mobsf_findings_are_normalized_and_html_is_removed() -> None:
    findings = MobSFAdapter.normalize_findings(
        {
            "manifest_analysis": {
                "manifest_findings": [
                    {
                        "rule": "android_task_hijacking",
                        "title": "<b>Task hijacking</b>",
                        "description": "Exported activity requires review",
                        "severity": "warning",
                        "component": ["com.example.MainActivity"],
                    }
                ]
            },
            "code_analysis": {
                "findings": {
                    "trust_all": {
                        "metadata": {
                            "description": "TLS validation is disabled",
                            "severity": "high",
                            "masvs": "MASVS-NETWORK",
                        },
                        "files": {"src/Tls.java": "line 4"},
                    }
                }
            },
        }
    )
    assert len(findings) == 2
    assert all(item.source == "mobsf" for item in findings)
    assert findings[0].title == "Task hijacking"
    assert {item.severity for item in findings} == {"medium", "high"}
    assert any(item.masvs == "MASVS-NETWORK" for item in findings)
