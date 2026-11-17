import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET


CONFIG = Path("/var/ossec/etc/ossec.conf")

LOG_FILES = {
    "control": {
        "watchdog": "/home/labadmin/deception-infra/runtime/watchdog.jsonl",
        "operations": "/home/labadmin/deception-infra/runtime/operations.jsonl",
    },
    "decoy": {
        "opencanary": "/var/log/deception/opencanary/events.json",
        "cowrie": "/var/log/deception/cowrie/cowrie.json",
    },
}


def values(element, tag):
    return [(child.text or "").strip() for child in element.findall(tag)]


def expected_sections(host):
    if host == "monitoring":
        yield "event-feed", "integration", {
            "name": "custom-deception-feed",
            "rule_id": "100202,100203,100204,100205",
            "alert_format": "json",
        }, "name"
        return

    for label, path in LOG_FILES[host].items():
        yield label, "localfile", {
            "location": path,
            "log_format": "json",
        }, "location"


def normalize_rule_ids(value):
    return sorted(part.strip() for part in value.split(","))


host = sys.argv[1]
try:
    text = CONFIG.read_text(encoding="utf-8-sig").lstrip()
    if text.startswith("<?xml"):
        text = text.split("?>", 1)[1]
    root = ET.fromstring("<config-file>" + text + "</config-file>")
except (OSError, ET.ParseError, IndexError) as exc:
    raise SystemExit(f"Не удалось прочитать {CONFIG}: {exc}")

configs = root.findall("ossec_config")
if not configs:
    raise SystemExit(f"В {CONFIG} отсутствует секция ossec_config")

missing = []
for label, tag, expected, identity in expected_sections(host):
    matches = [
        section
        for config in configs
        for section in config.findall(tag)
        if expected[identity] in values(section, identity)
    ]
    if len(matches) > 1:
        raise SystemExit(f"Дублирующая секция {tag}: {expected[identity]}")

    if matches:
        for field, required in expected.items():
            actual = values(matches[0], field)
            if field == "rule_id" and len(actual) == 1:
                if normalize_rule_ids(actual[0]) == normalize_rule_ids(required):
                    continue
            if actual != [required]:
                raise SystemExit(
                    f"Конфликт в секции {label}, поле {field}: "
                    f"ожидалось {required!r}, найдено {actual!r}"
                )
        continue

    lines = [f"  <{tag}>"]
    lines.extend(
        f"    <{field}>{value}</{field}>"
        for field, value in expected.items()
    )
    lines.append(f"  </{tag}>")
    missing.append({"label": label, "xml": "\n".join(lines)})

print(json.dumps(missing))
