from pathlib import Path

path = Path("app.py")
text = path.read_text(encoding="utf-8-sig")

old = '''            "packets": list(LIVE_MONITOR_PACKETS),
            "ai_predictions_enabled": False,
'''

new = '''            "packets": list(LIVE_MONITOR_PACKETS),
            "flow_count": len(LIVE_MONITOR_FLOWS),
            "flows": list(LIVE_MONITOR_FLOWS.values()),
            "ai_predictions_enabled": False,
'''

if text.count(old) != 1:
    raise SystemExit("ERROR: Status API section not found exactly once. No changes made.")

path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Flow data added to status API.")
