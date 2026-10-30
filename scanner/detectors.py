import ast
from pathlib import Path


def detect_sql_injection(file_path):
    findings = []

    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source)

    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue

        f_string_variables = {}

        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.JoinedStr):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            f_string_variables[target.id] = node.lineno

            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "execute"
                    and node.args
                ):
                    argument = node.args[0]

                    if isinstance(argument, ast.JoinedStr):
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "High",
                            "line": node.lineno,
                            "evidence": "SQL query uses an f-string.",
                            "file": str(file_path)
                        })

                    elif (
                        isinstance(argument, ast.Name)
                        and argument.id in f_string_variables
                    ):
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "High",
                            "line": f_string_variables[argument.id],
                            "evidence": "An f-string SQL query is passed to execute().",
                            "file": str(file_path)
                        })

    return findings


def detect_idor(file_path):
    findings = []

    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source)

    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue

        function_source = ast.get_source_segment(source, function)

        reads_user_id = (
            "request.args.get" in function_source
            and "user_id" in function_source
        )

        if not reads_user_id:
            continue

        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue

            if not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                continue

            sql = node.args[0].value.lower()

            if (
                "from orders" in sql
                and "where" in sql
                and "user_id" not in sql
            ):
                findings.append({
                    "type": "Broken Access Control (IDOR)",
                    "severity": "High",
                    "line": node.lineno,
                    "evidence": "Order query does not check order ownership.",
                    "file": str(file_path)
                })

    return findings