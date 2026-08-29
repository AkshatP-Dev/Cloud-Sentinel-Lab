#!/usr/bin/env python3
"""
Offline structural validator for the CloudSentinel Terraform tree.

This is NOT a substitute for `terraform validate` — it cannot check
provider schemas, resource argument names, or type correctness. It exists
because the sandbox this project was originally built in could not install
the terraform binary at all — its network egress allowlist blocked both
registry.terraform.io and releases.hashicorp.com (see TESTING.md's
"Explicitly NOT run here" section and README.md's build-status note).
What it DOES check, purely by parsing text:

  1. Every templatefile(path, {...}) call's argument keys exactly match
     the ${...} placeholders actually present in the target .tpl file —
     both directions, since Terraform's templatefile() errors on either a
     placeholder with no supplied value OR a supplied value never
     referenced by the template.
  2. Every file(path) call's target does NOT contain ${...} syntax (file()
     does not interpolate — if it did, that content would be embedded
     completely literally in the resulting IAM policy, which would be a
     bug).
  3. Every .tpl/.json policy file is valid JSON once ${...} placeholders
     are replaced with dummy strings (catches trailing commas, mismatched
     brackets, stray characters — anything a real IAM MalformedPolicyDocument
     error would also catch, but offline).
  4. Every var.NAME reference inside a module's main.tf/outputs.tf resolves
     to a variable actually declared in that module's variables.tf.
  5. Every referenced module source path (source = "../../modules/X")
     actually exists on disk.

Run: python3 scripts/dev/validate_tf_structure.py
Exits non-zero on any finding.
"""
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = REPO_ROOT / "terraform"

errors = []
warnings = []


def find_templatefile_calls(tf_path: Path):
    """Return list of (policy_relpath, arg_keys:set) for every templatefile() call."""
    text = tf_path.read_text()
    calls = []
    # templatefile("${path.module}/../../policies/X.json.tpl", { ... })
    for m in re.finditer(
        r'templatefile\(\s*"\$\{path\.module\}([^"]+)"\s*,\s*\{(.*?)\n\s*\}\s*\)',
        text,
        re.DOTALL,
    ):
        rel_path, body = m.groups()
        keys = set(re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=', body, re.MULTILINE))
        calls.append((rel_path, keys))
    return calls


def find_file_calls(tf_path: Path):
    text = tf_path.read_text()
    return re.findall(r'file\(\s*"\$\{path\.module\}([^"]+)"\s*\)', text)


def tpl_placeholders(tpl_path: Path):
    text = tpl_path.read_text()
    return set(re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', text))


def check_json_validity(tpl_path: Path):
    text = tpl_path.read_text()
    # Replace every ${...} with a dummy JSON-safe string so real JSON
    # syntax (commas, brackets, quoting) can still be validated.
    dummy = re.sub(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}', 'DUMMY', text)
    try:
        json.loads(dummy)
    except json.JSONDecodeError as e:
        errors.append(f"{tpl_path.relative_to(REPO_ROOT)}: invalid JSON after stripping interpolation: {e}")


def check_iam_statement_grammar(tpl_path: Path):
    text = tpl_path.read_text()
    dummy = re.sub(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}', 'DUMMY', text)
    try:
        doc = json.loads(dummy)
    except json.JSONDecodeError:
        return  # already reported by check_json_validity
    allowed_top = {"Version", "Id", "Statement"}
    allowed_stmt = {
        "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
        "Resource", "NotResource", "Condition",
    }
    extra_top = set(doc.keys()) - allowed_top
    if extra_top:
        errors.append(f"{tpl_path.relative_to(REPO_ROOT)}: unexpected top-level policy key(s): {extra_top}")
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for i, stmt in enumerate(stmts):
        extra = set(stmt.keys()) - allowed_stmt
        if extra:
            errors.append(f"{tpl_path.relative_to(REPO_ROOT)}: Statement[{i}] has unexpected key(s): {extra}")
        if "Effect" not in stmt or stmt["Effect"] not in ("Allow", "Deny"):
            errors.append(f"{tpl_path.relative_to(REPO_ROOT)}: Statement[{i}] missing/invalid Effect")


def check_braces_balanced(tf_path: Path):
    text = tf_path.read_text()
    # Strip strings and comments crudely to avoid counting braces inside
    # JSON-ish heredocs or comments as structural.
    no_comments = re.sub(r'#.*', '', text)
    no_comments = re.sub(r'//.*', '', no_comments)
    depth = 0
    for ch in no_comments:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
        if depth < 0:
            errors.append(f"{tf_path.relative_to(REPO_ROOT)}: unbalanced braces (closed before opened)")
            return
    if depth != 0:
        errors.append(f"{tf_path.relative_to(REPO_ROOT)}: unbalanced braces (final depth {depth})")


def check_module_var_usage(module_dir: Path):
    vars_tf = module_dir / "variables.tf"
    declared = set()
    if vars_tf.exists():
        declared = set(re.findall(r'variable\s+"([A-Za-z0-9_]+)"', vars_tf.read_text()))
    for tf_file in module_dir.glob("*.tf"):
        if tf_file.name == "variables.tf":
            continue
        text = tf_file.read_text()
        used = set(re.findall(r'\bvar\.([A-Za-z0-9_]+)', text))
        missing = used - declared
        if missing:
            errors.append(f"{tf_file.relative_to(REPO_ROOT)}: references var.X not declared in variables.tf: {missing}")


def check_module_sources(tf_path: Path):
    text = tf_path.read_text()
    for m in re.finditer(r'module\s+"[^"]+"\s*\{[^}]*?source\s*=\s*"([^"]+)"', text, re.DOTALL):
        rel = m.group(1)
        target = (tf_path.parent / rel).resolve()
        if not target.exists():
            errors.append(f"{tf_path.relative_to(REPO_ROOT)}: module source does not exist: {rel} -> {target}")


def main():
    tf_files = sorted(TF_ROOT.rglob("*.tf"))
    tpl_files = sorted(list(TF_ROOT.rglob("*.tpl")) + [
        p for p in TF_ROOT.rglob("*.json") if ".tpl" not in p.suffixes
    ])

    print(f"Found {len(tf_files)} .tf files, {len(tpl_files)} policy JSON/.tpl files.\n")

    for tpl in tpl_files:
        check_json_validity(tpl)
        check_iam_statement_grammar(tpl)

    for tf in tf_files:
        check_braces_balanced(tf)
        check_module_sources(tf)
        for rel_path, arg_keys in find_templatefile_calls(tf):
            tpl_path = (tf.parent / rel_path.lstrip("/")).resolve()
            if not tpl_path.exists():
                errors.append(f"{tf.relative_to(REPO_ROOT)}: templatefile() target does not exist: {rel_path}")
                continue
            placeholders = tpl_placeholders(tpl_path)
            missing_args = placeholders - arg_keys
            extra_args = arg_keys - placeholders
            if missing_args:
                errors.append(
                    f"{tf.relative_to(REPO_ROOT)} -> {tpl_path.name}: "
                    f"template needs {missing_args} but templatefile() call doesn't supply them"
                )
            if extra_args:
                errors.append(
                    f"{tf.relative_to(REPO_ROOT)} -> {tpl_path.name}: "
                    f"templatefile() supplies {extra_args} but template never uses them "
                    f"(terraform errors on unused template vars)"
                )
        for rel_path in find_file_calls(tf):
            file_path = (tf.parent / rel_path.lstrip("/")).resolve()
            if not file_path.exists():
                errors.append(f"{tf.relative_to(REPO_ROOT)}: file() target does not exist: {rel_path}")
                continue
            if "${" in file_path.read_text():
                errors.append(
                    f"{tf.relative_to(REPO_ROOT)}: file() target {rel_path} contains \\${{...}} syntax "
                    f"but file() does not interpolate — use templatefile() instead"
                )

    for module_dir in sorted((TF_ROOT / "modules").iterdir()):
        if module_dir.is_dir():
            check_module_var_usage(module_dir)
    check_module_var_usage(TF_ROOT / "environments" / "lab")

    if errors:
        print(f"FAIL — {len(errors)} issue(s):\n")
        for e in errors:
            print(f"  ✗ {e}")
        sys.exit(1)
    else:
        print("PASS — no structural issues found across templatefile()/file() wiring, "
              "JSON/IAM-grammar validity, brace balance, module sources, and var.X declarations.")
        if warnings:
            print(f"\n{len(warnings)} warning(s):")
            for w in warnings:
                print(f"  ! {w}")


if __name__ == "__main__":
    main()
