from pathlib import Path

app_path = Path("app.py")
helper_path = Path("flow_helpers.tmp")

app = app_path.read_text(encoding="utf-8-sig")
helpers = helper_path.read_text(encoding="utf-8-sig").strip()
anchor = "LIVE_MONITOR_PACKETS = deque(maxlen=100)"

if app.count(anchor) != 1:
    raise SystemExit("ERROR: Insertion point not found exactly once. app.py unchanged.")

if "def _update_live_flow(record, packet_length):" in app:
    raise SystemExit("ERROR: Flow helpers already exist. app.py unchanged.")

app = app.replace(anchor, anchor + "\n\n\n" + helpers, 1)
app_path.write_text(app, encoding="utf-8")
print("Flow helpers inserted successfully.")
