import json
import subprocess
import sys

SENSORS = {
    "opencanary": (
        "opencanary-01",
        "/opencanary/.venv/bin/python",
    ),
    "cowrie": (
        "cowrie-01",
        "/cowrie/cowrie-env/bin/python",
    ),
}

REMOTE_CODE = r'''
import http.client
import json
import socket
import sys

sensor = sys.argv[1]
checks = {}

def banner(name, port, prefix):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(2)
            value = s.recv(512)
        checks[name] = {
            "ok": value.startswith(prefix),
            "response": value.decode(errors="replace").strip(),
        }
    except Exception as e:
        checks[name] = {"ok": False, "error": str(e)}

if sensor == "opencanary":
    connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=2)
    try:
        connection.request("GET", "/index.html")
        response = connection.getresponse()
        response.read(1)
        checks["http"] = {
            "ok": response.status == 200,
            "status": response.status,
        }
    except Exception as e:
        checks["http"] = {"ok": False, "error": str(e)}
    finally:
        connection.close()

    banner("ftp", 21, b"220")

elif sensor == "cowrie":
    banner("ssh", 2222, b"SSH-2.0-")

print(json.dumps({
    "healthy": bool(checks) and all(c["ok"] for c in checks.values()),
    "checks": checks,
}))
'''


def probe(sensor):
    container, python = SENSORS[sensor]
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "decoy",
                f"docker exec -i {container} {python} - {sensor}",
            ],
            input=REMOTE_CODE,
            capture_output=True,
            text=True,
            timeout=25,
        )
        if result.returncode != 0:
            return {
                "healthy": None,
                "error": result.stderr.strip() or "docker exec failed",
            }

        data = json.loads(result.stdout)
        if not isinstance(data.get("healthy"), bool):
            raise ValueError("Invalid health response")
        return data

    except (subprocess.TimeoutExpired, ValueError) as e:
        return {"healthy": None, "error": str(e)}


def probe_services(states, log):
    states = dict(states)

    for sensor, (container, _) in SENSORS.items():
        if states.get(container) != "running":
            continue

        result = probe(sensor)

        if result["healthy"] is False:
            states[container] = "unhealthy"
            log("service_check_failed", sensor=sensor,
                checks=result["checks"])

        elif result["healthy"] is None:
            states[container] = "check_unavailable"
            log("service_check_unavailable", sensor=sensor,
                error=result["error"])

    return states


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in SENSORS:
        raise SystemExit("Usage: health_probe.py opencanary|cowrie")

    result = probe(sys.argv[1])
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if result["healthy"] is True:
        sys.exit(0)
    elif result["healthy"] is False:
        sys.exit(1)
    else:
        sys.exit(2)
