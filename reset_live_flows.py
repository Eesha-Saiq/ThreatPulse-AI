from pathlib import Path

path = Path("app.py")
text = path.read_text(encoding="utf-8-sig")

old = '''        LIVE_MONITOR_PACKETS.clear()
        LIVE_MONITOR_STATE.update({
'''

new = '''        LIVE_MONITOR_PACKETS.clear()
        LIVE_MONITOR_FLOWS.clear()
        LIVE_MONITOR_STATE.update({
'''

if text.count(old) != 1:
    raise SystemExit("ERROR: Expected Start route section not found exactly once. No changes made.")

path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Flow reset added to Start route.")
