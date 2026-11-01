# ThreatPulse AI — Starter Foundation

A local-first Flask application scaffold for the ThreatPulse AI university project.
The interface uses a dark navy / purple cybersecurity theme.

## What works in this starter
- Local Flask web app and consistent sidebar navigation.
- SQLite persistence for dataset validation history and explicitly simulated placeholder events.
- CSV upload and a small schema/row preview.
- Searchable-style history tables and finding review action.
- System-readiness page that clearly distinguishes configured from not-yet-configured components.

## What is intentionally NOT implemented yet
- No trained model is included and no AI predictions are made.
- Live packet capture is not implemented.
- The demo button only creates a clearly labelled database placeholder; it does not generate network traffic.
- Sequential, Pthreads, OpenMP and MPI benchmarks are not implemented yet.
- PDF/CSV report generation is a later milestone.

Do not present placeholder events or example empty states as real detections or benchmark measurements.

## Run on Windows using VS Code
1. Extract this ZIP to a folder such as `D:\\Projects\\ThreatPulse-AI`.
2. Open that folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
5. Activate it:
   ```powershell
   .\\.venv\\Scripts\\Activate.ps1
   ```
   If PowerShell blocks activation, use the VS Code Command Prompt terminal and run:
   ```bat
   .venv\\Scripts\\activate.bat
   ```
6. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
7. Start the app:
   ```powershell
   python app.py
   ```
8. Open `http://127.0.0.1:5000` in your browser.
9. Stop the server with `Ctrl+C`.

## Next implementation milestones
1. Confirm laptop environment and project rubric.
2. Choose a public dataset and define its feature/label schema.
3. Build a real preprocessing + Random Forest training/evaluation pipeline.
4. Implement the common deterministic workload and verify all PDC variants.
5. Implement authorized live capture and compatible flow-feature extraction.
6. Integrate safe replay/demo, reporting, tests and final documentation.

## Privacy and safety
- The app binds to localhost by default.
- Uploaded CSV files are stored under `datasets/uploads/`; do not upload sensitive traffic data.
- Only monitor networks and interfaces you are authorized to inspect.
- The app does not block traffic or change firewall settings.
