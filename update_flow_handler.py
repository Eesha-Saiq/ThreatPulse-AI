from pathlib import Path

path = Path("app.py")
text = path.read_text(encoding="utf-8-sig")

old = '''        with LIVE_MONITOR_LOCK:
            if not LIVE_MONITOR_STATE["active"]:
                return

            LIVE_MONITOR_STATE["packets_seen"] += 1
'''

new = '''        _update_live_flow(record, len(packet))

        with LIVE_MONITOR_LOCK:
            if not LIVE_MONITOR_STATE["active"]:
                return

            LIVE_MONITOR_STATE["packets_seen"] += 1
'''

if text.count(old) != 1:
    raise SystemExit("ERROR: Exact packet-handler section not found once. No changes made.")

text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
print("Packet handler updated successfully.")
