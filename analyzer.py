"""Detect successful logging tampering, root activity and failed console logins in CloudTrail records."""

def analyze(data):
    out = []
    for e in data.get("Records", []):
        name = e.get("eventName")
        success = not e.get("errorCode")
        reason = None
        if success and name in {"StopLogging", "DeleteTrail", "DeleteEventDataStore"}:
            reason = ("HIGH", "LOGGING_TAMPER", "Successful operation can reduce audit visibility.", "Verify change authorization and restore required logging.")
        elif success and e.get("userIdentity", {}).get("type") == "Root":
            reason = ("HIGH", "ROOT_ACTIVITY", "Root identity performed an operation.", "Validate business justification and use delegated identities.")
        elif name == "ConsoleLogin" and e.get("responseElements", {}).get("ConsoleLogin") == "Failure":
            reason = ("MEDIUM", "LOGIN_FAILURE", "Console login failed; one event does not establish an attack.", "Correlate source IP, identity and repeated failures.")
        if reason:
            severity, check, detail, remediation = reason
            out.append(finding(e.get("eventID", "unknown"), severity, check, detail, remediation, e))
    return out

import argparse
import json
import sys
from pathlib import Path

def finding(resource, severity, check, detail, remediation, evidence):
    return dict(resource=resource, severity=severity, check=check, detail=detail, remediation=remediation, evidence=evidence)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--fail-on-high", action="store_true")
    args = p.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        results = analyze(data)
        text = json.dumps({"results": results, "count": len(results), "scope": __doc__}, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(r["severity"] == "HIGH" for r in results))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        print(f"Input/report error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

