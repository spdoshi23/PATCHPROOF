from scanner.analyzer import scan_application


def test_scanner_detects_vulnerabilities():
    target = "vulnerable_app/app.py"

    findings = scan_application(target)

    vulnerability_types = [
        finding["type"] for finding in findings
    ]

    print("\nSCANNER FINDINGS:")

    for finding in findings:
        print(finding)

    assert "SQL Injection" in vulnerability_types
    assert "Broken Access Control (IDOR)" in vulnerability_types