from scanner.detectors import (
    detect_sql_injection,
    detect_idor
)


def scan_application(target_file):
    findings = []

    findings.extend(detect_sql_injection(target_file))
    findings.extend(detect_idor(target_file))

    return findings