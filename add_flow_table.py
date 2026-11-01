from pathlib import Path
import shutil

path = Path("frontend/templates/live_monitor.html")
text = path.read_text(encoding="utf-8-sig")

section_anchor = "<script>\n(() => {"
js_anchor = '  const packetTable = document.getElementById("packet-table");'
refresh_anchor = "  async function refreshStatus() {"
packets_anchor = "      renderPackets(data.packets);"

checks = [
    (section_anchor, 1),
    (js_anchor, 1),
    (refresh_anchor, 1),
    (packets_anchor, 1),
]

for anchor, expected in checks:
    if text.count(anchor) != expected:
        raise SystemExit(
            "ERROR: Expected HTML/JavaScript insertion point not found exactly once. "
            "No changes made."
        )

if 'id="flow-table"' in text or "function renderFlows(flows)" in text:
    raise SystemExit("ERROR: Flow table already exists. No changes made.")

flow_section = """<section class="panel" style="margin-top:20px">
  <div class="panel-header">
    <div>
      <h2>Aggregated network flows</h2>
      <p class="subheading">Bidirectional flow summaries. Metadata only; no packet payloads.</p>
    </div>
    <span class="status-pill" id="flow-count">0 flows</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Protocol</th>
          <th>Endpoint A</th>
          <th>Endpoint B</th>
          <th>Packets</th>
          <th>Bytes</th>
          <th>First seen</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody id="flow-table">
        <tr><td colspan="7">Start monitoring to collect flows.</td></tr>
      </tbody>
    </table>
  </div>
</section>

"""

render_function = """  function renderFlows(flows) {
    const flowTable = document.getElementById("flow-table");
    const flowCount = document.getElementById("flow-count");
    flowTable.replaceChildren();

    flowCount.textContent = `${(flows || []).length} flows`;

    if (!flows || !flows.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 7;
      cell.textContent = "No flows observed yet.";
      row.appendChild(cell);
      flowTable.appendChild(row);
      return;
    }

    for (const flow of flows) {
      const row = document.createElement("tr");
      const values = [
        flow.protocol,
        flow.endpoint_a,
        flow.endpoint_b,
        flow.packets,
        flow.bytes,
        flow.first_seen,
        flow.last_seen
      ];

      for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = String(value ?? "");
        row.appendChild(cell);
      }

      flowTable.appendChild(row);
    }
  }

"""

updated = text.replace(section_anchor, flow_section + section_anchor, 1)
updated = updated.replace(js_anchor, js_anchor + "\n", 1)
updated = updated.replace(refresh_anchor, render_function + refresh_anchor, 1)
updated = updated.replace(packets_anchor, packets_anchor + "\n      renderFlows(data.flows);", 1)

backup = path.with_name("live_monitor.html.before_flow_table.bak")
if not backup.exists():
    shutil.copy2(path, backup)

path.write_text(updated, encoding="utf-8")
print("Flow table added successfully.")
print("Backup:", backup)
