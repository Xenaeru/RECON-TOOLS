import sys, json
from orchestrator import run

if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    path, rep = run(cfg)
    print(f"[+] report: {path}")
    print(json.dumps({"findings": [f.__dict__ for f in rep.findings],
                      "ports": rep.open_ports}, default=str, indent=2))
