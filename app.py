
from pathlib import Path
import sqlite3
from datetime import datetime
import threading
import time
from collections import deque

import joblib
import pandas as pd
from scapy.all import sniff, IP, IPv6, TCP, UDP, conf
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)

# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "datasets" / "uploads"
MODEL_DIR = BASE_DIR / "models"

INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = INSTANCE_DIR / "threatpulse.db"
MODEL_PATH = MODEL_DIR / "threatpulse_model.joblib"

MAX_UPLOAD_MB = 500
MAX_ANALYSIS_ROWS = None
MAX_AI_FINDINGS = 500

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static",
)

app.config["SECRET_KEY"] = "change-this-local-development-key"
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            status TEXT NOT NULL,
            row_count INTEGER DEFAULT 0,
            column_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            message TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            review_status TEXT NOT NULL DEFAULT 'Needs review'
        );
        """)


init_db()


# --------------------------------------------------
# NAVIGATION
# --------------------------------------------------

NAV_ITEMS = [
    ("Overview", "dashboard", "layout-dashboard"),
    ("Dataset Analysis", "analysis", "file-up"),
    ("Live Monitor", "live_monitor", "activity"),
    ("Demo Mode", "demo_mode", "flask-conical"),
    ("Threat Findings", "findings", "shield-alert"),
    ("Performance Lab", "performance", "gauge"),
    ("Reports & History", "history", "history"),
    ("Settings", "settings", "settings"),
]


@app.context_processor
def inject_globals():
    return {
        "nav_items": NAV_ITEMS,
        "current_endpoint": request.endpoint,
    }


# --------------------------------------------------
# AI MODEL
# --------------------------------------------------

def load_trained_model():
    """Load the locally trained ThreatPulse model."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Trained model not found. Run train_model.py first."
        )

    return joblib.load(MODEL_PATH)


def predict_dataset(frame):
    """
    Predict normal or potential attack labels for a CSV dataset.

    This is a baseline model trained on a limited sample.
    Predictions are preliminary and must not be treated as
    confirmed security incidents.
    """
    model = load_trained_model()

    if not hasattr(model, "feature_names_in_"):
        raise ValueError(
            "The saved model has no feature schema. "
            "Retrain the model first."
        )

    expected_columns = list(model.feature_names_in_)

    features = frame.copy()
    features.columns = features.columns.astype(str).str.strip()

    # Match the uploaded dataset to the model's training features.
    features = features.reindex(columns=expected_columns)

    # This baseline pipeline expects numeric input features.
    numeric_columns = [
    column for column in expected_columns
    if column not in ["proto", "state", "service"]
]

for column in numeric_columns:
    features[column] = pd.to_numeric(
        features[column],
        errors="coerce",
    )

    features = features.replace(
        [float("inf"), float("-inf")],
        float("nan"),
    )

    predictions = model.predict(features)

    attack_count = int((predictions == 1).sum())
    normal_count = int((predictions == 0).sum())

    attack_confidence = None

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)

        classes = list(model.classes_)

        if 1 in classes:
            attack_index = classes.index(1)
            attack_confidence = (
                probabilities[:, attack_index] * 100
            )

    return {
        "total": int(len(predictions)),
        "normal": normal_count,
        "attacks": attack_count,
        "predictions": predictions,
        "attack_confidence": attack_confidence,
    }


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------

def save_scan(filename, status, row_count, column_count, message):
    with get_db() as db:
        db.execute(
            """
            INSERT INTO scans
            (filename, status, row_count, column_count,
             created_at, message)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                status,
                row_count,
                column_count,
                datetime.now().isoformat(timespec="seconds"),
                str(message)[:1000],
            ),
        )


def save_ai_prediction_events(
    frame,
    result,
    filename,
    limit=MAX_AI_FINDINGS,
):
    """
    Save up to 'limit' AI-predicted attack records.

    Existing AI Prediction findings are replaced by findings
    from the latest completed dataset analysis. Simulated events
    are preserved. These findings are not verified incidents.
    """
    predictions = result["predictions"]
    confidence = result.get("attack_confidence")

    attack_indexes = [
        int(index)
        for index, prediction in enumerate(predictions)
        if prediction == 1
    ]

    selected_indexes = attack_indexes[:limit]
    now = datetime.now().isoformat(timespec="seconds")

    rows_to_insert = []

    for index in selected_indexes:
        row = frame.iloc[index]

        details = []

        # Include common network fields when present.
        useful_columns = (
            "srcip",
            "dstip",
            "sport",
            "dsport",
            "proto",
            "service",
            "state",
        )

        for column in useful_columns:
            if column in frame.columns and pd.notna(row[column]):
                details.append(f"{column}={row[column]}")

        confidence_text = ""

        if confidence is not None:
            confidence_text = (
                f" Model attack probability: "
                f"{float(confidence[index]):.1f}%."
            )

        reason = (
            f"AI model predicted a potential attack in "
            f"{filename}, data row {index + 1}."
            f"{confidence_text}"
        )

        if details:
            reason += " Record details: " + ", ".join(details)

        rows_to_insert.append((
            "AI Prediction",
            "Potential attack",
            "Unverified",
            reason[:1000],
            now,
            "Needs review",
        ))

    with get_db() as db:
        # Keep simulated Demo Mode events untouched.
        db.execute(
            "DELETE FROM events WHERE source_type = ?",
            ("AI Prediction",),
        )

        if rows_to_insert:
            db.executemany(
                """
                INSERT INTO events
                (source_type, event_type, severity, reason,
                 created_at, review_status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows_to_insert,
            )

    return len(rows_to_insert)


# --------------------------------------------------
# OVERVIEW / DASHBOARD
# --------------------------------------------------

@app.route("/")

@app.route("/")
def dashboard():
    import json

    with get_db() as db:
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()

        scan_count = db.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        event_count = db.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        recent_events = db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 5"
        ).fetchall()

    # Check whether the trained model file exists
    model_ready = MODEL_PATH.exists()

    # Validate the saved PDC benchmark report
    pdc_ready = False
    pdc_message = "Benchmark report not found."

    pdc_path = BASE_DIR / "reports" / "pdc_benchmarks.json"

    try:
        with pdc_path.open("r", encoding="utf-8") as file:
            pdc_data = json.load(file)

        if isinstance(pdc_data, dict) and pdc_data.get("workload"):
            pdc_ready = True
            pdc_message = "Benchmark results available."
        else:
            pdc_message = "Benchmark report needs verification."
    except (OSError, json.JSONDecodeError):
        pdc_message = "Benchmark report unavailable or invalid."

    return render_template(
        "dashboard.html",
        scans=scans,
        scan_count=scan_count,
        event_count=event_count,
        recent_events=recent_events,
        model_ready=model_ready,
        pdc_ready=pdc_ready,
        pdc_message=pdc_message,
    )



# --------------------------------------------------
# DATASET ANALYSIS WITH AI PREDICTIONS
# --------------------------------------------------

@app.route("/analysis", methods=["GET", "POST"])
def analysis():
    preview = None
    columns = []
    prediction_summary = None

    if request.method == "POST":
        uploaded = request.files.get("dataset")

        if not uploaded or not uploaded.filename:
            flash("Please choose a CSV file first.", "error")
            return redirect(url_for("analysis"))

        if not uploaded.filename.lower().endswith(".csv"):
            flash("Only CSV files are accepted.", "error")
            return redirect(url_for("analysis"))

        # Prevent user-supplied path components from being used.
        safe_name = Path(uploaded.filename).name

        saved_name = (
            f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_"
            f"{safe_name}"
        )
        saved_path = UPLOAD_DIR / saved_name

        try:
            uploaded.save(saved_path)

            # Loads all rows. Very large files may require substantial RAM.
            frame = pd.read_csv(
                saved_path,
                low_memory=False,
            )

            if frame.empty or len(frame.columns) == 0:
                raise ValueError(
                    "The CSV has no readable rows or columns."
                )

            frame.columns = frame.columns.astype(str).str.strip()

            # Build dataset schema information.
            columns = [
                {
                    "name": str(column),
                    "dtype": str(frame[column].dtype),
                    "missing": int(frame[column].isna().sum()),
                }
                for column in frame.columns
            ]

            # Show a small preview, not the entire dataset.
            preview = (
                frame.head(8)
                .fillna("")
                .to_dict(orient="records")
            )

            # Run the saved AI model on the full dataframe.
            result = predict_dataset(frame)

            # Save a bounded number of predicted attacks for Findings.
            saved_findings = save_ai_prediction_events(
                frame,
                result,
                safe_name,
                limit=MAX_AI_FINDINGS,
            )

            prediction_summary = {
                "total": result["total"],
                "normal": result["normal"],
                "attacks": result["attacks"],
            }

            message = (
                f"AI predictions completed on {result['total']} rows. "
                f"Potential attacks: {result['attacks']}; "
                f"normal traffic: {result['normal']}. "
                f"Saved {saved_findings} potential attack findings "
                f"for review."
            )

            save_scan(
                safe_name,
                "AI prediction complete",
                len(frame),
                len(frame.columns),
                message,
            )

            flash(message, "success")

        except Exception as exc:
            error_message = f"{type(exc).__name__}: {exc}"

            save_scan(
                safe_name,
                "Prediction failed",
                0,
                0,
                error_message,
            )

            flash(
                f"Could not analyse this CSV: {error_message}",
                "error",
            )

    return render_template(
        "analysis.html",
        preview=preview,
        columns=columns,
        prediction_summary=prediction_summary,
    )


# --------------------------------------------------
# LIVE MONITOR
# --------------------------------------------------

@app.route("/live-monitor")
def live_monitor():
    return render_template("live_monitor.html")


@app.route("/api/live-monitor/interfaces", methods=["GET"])
def live_monitor_interfaces():
    """List available interfaces for authorized local monitoring."""
    try:
        interfaces = []

        for interface in conf.ifaces.values():
            interfaces.append({
                "name": str(interface.name),
                "description": str(
                    getattr(interface, "description", "") or interface.name
                ),
            })

        return jsonify({
            "ok": True,
            "interfaces": interfaces,
            "capture_active": False,
            "message": "Interface discovery only; packet capture is not running.",
        })

    except Exception:
        app.logger.exception("Live Monitor interface discovery failed")
        return jsonify({
            "ok": False,
            "interfaces": [],
            "capture_active": False,
            "message": "Could not list network interfaces.",
        }), 500



# Live capture state: bounded in-memory metadata only.
LIVE_MONITOR_LOCK = threading.Lock()
LIVE_MONITOR_STATE = {
    "active": False,
    "interface": None,
    "sniffer": None,
    "packets_seen": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "error": None,
}
LIVE_MONITOR_PACKETS = deque(maxlen=100)


LIVE_MONITOR_FLOWS = {}
LIVE_MONITOR_FLOW_LIMIT = 500

# Bounded metadata-only heuristic alert state.
LIVE_MONITOR_ALERTS = deque(maxlen=100)
LIVE_MONITOR_RECENT_ACTIVITY = deque()
LIVE_MONITOR_ALERTED_FLOWS = {}
LIVE_MONITOR_ALERT_WINDOW_SECONDS = 10
LIVE_MONITOR_ALERT_PACKET_THRESHOLD = 100
LIVE_MONITOR_ALERT_COOLDOWN_SECONDS = 30
LIVE_MONITOR_ALERT_ID = 0



def _record_live_heuristic_alert(record, flow_key):
    """Create bounded, metadata-only alerts for unusually high packet rates."""
    global LIVE_MONITOR_ALERT_ID

    now = time.time()
    window = LIVE_MONITOR_ALERT_WINDOW_SECONDS

    with LIVE_MONITOR_LOCK:
        if not LIVE_MONITOR_STATE["active"]:
            return

        LIVE_MONITOR_RECENT_ACTIVITY.append(
            (now, record["source_ip"], record["destination_ip"])
        )

        while (
            LIVE_MONITOR_RECENT_ACTIVITY
            and now - LIVE_MONITOR_RECENT_ACTIVITY[0][0] > window
        ):
            LIVE_MONITOR_RECENT_ACTIVITY.popleft()

        packet_rate_count = sum(
            1 for _, src, _ in LIVE_MONITOR_RECENT_ACTIVITY
            if src == record["source_ip"]
        )

        if packet_rate_count < LIVE_MONITOR_ALERT_PACKET_THRESHOLD:
            return

        cooldown_key = ("source_rate", record["source_ip"])
        last_alert = LIVE_MONITOR_ALERTED_FLOWS.get(cooldown_key, 0)

        if now - last_alert < LIVE_MONITOR_ALERT_COOLDOWN_SECONDS:
            return

        LIVE_MONITOR_ALERTED_FLOWS[cooldown_key] = now
        LIVE_MONITOR_ALERT_ID += 1

        LIVE_MONITOR_ALERTS.append({
            "id": LIVE_MONITOR_ALERT_ID,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "warning",
            "type": "High packet rate",
            "source_ip": record["source_ip"],
            "destination_ip": record["destination_ip"],
            "protocol": record["protocol"],
            "observed_packets": packet_rate_count,
            "window_seconds": window,
            "message": (
                f"Source generated {packet_rate_count} packets "
                f"within {window} seconds. Review this activity."
            ),
            "classification": "heuristic",
        })

        if len(LIVE_MONITOR_ALERTED_FLOWS) > 1000:
            LIVE_MONITOR_ALERTED_FLOWS.clear()

def _live_flow_key(source_ip, destination_ip, protocol, source_port, destination_port):
    """Build a direction-independent key for a bidirectional flow."""
    endpoint_a = (str(source_ip), int(source_port or 0))
    endpoint_b = (str(destination_ip), int(destination_port or 0))
    first, second = sorted((endpoint_a, endpoint_b))
    return (str(protocol), first, second)


def _update_live_flow(record, packet_length):
    """Aggregate packet metadata and lengths; never retain payloads."""
    key = _live_flow_key(
        record["source_ip"],
        record["destination_ip"],
        record["protocol"],
        record["source_port"],
        record["destination_port"],
    )

    with LIVE_MONITOR_LOCK:
        if not LIVE_MONITOR_STATE["active"]:
            return

        flow = LIVE_MONITOR_FLOWS.get(key)
        if flow is None:
            if len(LIVE_MONITOR_FLOWS) >= LIVE_MONITOR_FLOW_LIMIT:
                oldest_key = next(iter(LIVE_MONITOR_FLOWS))
                LIVE_MONITOR_FLOWS.pop(oldest_key, None)

            flow = {
                "protocol": record["protocol"],
                "endpoint_a": f'{record["source_ip"]}:{record["source_port"] or 0}',
                "endpoint_b": f'{record["destination_ip"]}:{record["destination_port"] or 0}',
                "packets": 0,
                "bytes": 0,
                "first_seen": record["time"],
                "last_seen": record["time"],
            }
            LIVE_MONITOR_FLOWS[key] = flow

        flow["packets"] += 1
        flow["bytes"] += max(0, int(packet_length))
        flow["last_seen"] = record["time"]


def _live_packet_metadata(packet):
    """Extract headers only; never store packet payloads."""
    try:
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            return

        protocol = "Other"
        source_port = None
        destination_port = None

        if TCP in packet:
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

        record = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "source_ip": str(source_ip),
            "destination_ip": str(destination_ip),
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
        }

        _update_live_flow(record, len(packet))
        _record_live_heuristic_alert(record, None)

        with LIVE_MONITOR_LOCK:
            if not LIVE_MONITOR_STATE["active"]:
                return

            LIVE_MONITOR_STATE["packets_seen"] += 1
            if protocol == "TCP":
                LIVE_MONITOR_STATE["tcp_count"] += 1
            elif protocol == "UDP":
                LIVE_MONITOR_STATE["udp_count"] += 1
            LIVE_MONITOR_PACKETS.appendleft(record)

    except Exception:
        app.logger.debug("Skipped a packet that could not be parsed.", exc_info=True)


@app.route("/api/live-monitor/start", methods=["POST"])
def live_monitor_start():
    payload = request.get_json(silent=True) or {}
    interface_name = payload.get("interface")

    if not isinstance(interface_name, str) or not interface_name.strip():
        return jsonify({"ok": False, "message": "Select a network interface first."}), 400

    interface = next(
        (item for item in conf.ifaces.values() if item.name == interface_name),
        None,
    )
    if interface is None:
        return jsonify({"ok": False, "message": "That interface is not available."}), 400

    with LIVE_MONITOR_LOCK:
        if LIVE_MONITOR_STATE["active"]:
            return jsonify({
                "ok": False,
                "message": "Monitoring is already active.",
            }), 409

        LIVE_MONITOR_PACKETS.clear()
        LIVE_MONITOR_FLOWS.clear()
        LIVE_MONITOR_STATE.update({
            "active": True,
            "interface": interface_name,
            "sniffer": None,
            "packets_seen": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "error": None,
        })

    try:
        sniffer = __import__("scapy.all", fromlist=["AsyncSniffer"]).AsyncSniffer(
            iface=interface,
            prn=_live_packet_metadata,
            store=False,
        )
        with LIVE_MONITOR_LOCK:
            LIVE_MONITOR_STATE["sniffer"] = sniffer

        sniffer.start()

        return jsonify({
            "ok": True,
            "message": f"Monitoring started on {interface_name}.",
            "capture_active": True,
        })

    except Exception:
        app.logger.exception("Could not start Live Monitor capture.")
        with LIVE_MONITOR_LOCK:
            LIVE_MONITOR_STATE.update({
                "active": False,
                "interface": None,
                "sniffer": None,
                "error": "Capture could not start. Check interface and permissions.",
            })
        return jsonify({
            "ok": False,
            "message": "Capture could not start. Check interface and permissions.",
        }), 500


@app.route("/api/live-monitor/stop", methods=["POST"])
def live_monitor_stop():
    with LIVE_MONITOR_LOCK:
        sniffer = LIVE_MONITOR_STATE["sniffer"]
        active = LIVE_MONITOR_STATE["active"]
        LIVE_MONITOR_STATE["active"] = False

    if sniffer is not None and active:
        try:
            sniffer.stop(join=True)
        except Exception:
            app.logger.exception("Error stopping Live Monitor capture.")
            with LIVE_MONITOR_LOCK:
                LIVE_MONITOR_STATE["error"] = "Capture stopped with a warning."

    with LIVE_MONITOR_LOCK:
        LIVE_MONITOR_STATE["sniffer"] = None
        LIVE_MONITOR_STATE["interface"] = None

    return jsonify({
        "ok": True,
        "message": "Monitoring stopped.",
        "capture_active": False,
    })


@app.route("/api/live-monitor/status", methods=["GET"])
def live_monitor_status():
    with LIVE_MONITOR_LOCK:
        state = {
            "capture_active": LIVE_MONITOR_STATE["active"],
            "interface": LIVE_MONITOR_STATE["interface"],
            "packets_seen": LIVE_MONITOR_STATE["packets_seen"],
            "tcp_count": LIVE_MONITOR_STATE["tcp_count"],
            "udp_count": LIVE_MONITOR_STATE["udp_count"],
            "error": LIVE_MONITOR_STATE["error"],
            "packets": list(LIVE_MONITOR_PACKETS),
            "flow_count": len(LIVE_MONITOR_FLOWS),
            "flows": list(LIVE_MONITOR_FLOWS.values()),
            "alerts": list(LIVE_MONITOR_ALERTS),
            "ai_predictions_enabled": False,
        }

    return jsonify({"ok": True, **state})


# --------------------------------------------------
# DEMO MODE
# --------------------------------------------------

@app.route("/demo-mode", methods=["GET", "POST"])
def demo_mode():
    if request.method == "POST":
        scenario = request.form.get(
            "scenario",
            "Benign test event",
        )

        # This is a simulated event, not a real detection.
        with get_db() as db:
            db.execute(
                """
                INSERT INTO events
                (source_type, event_type, severity, reason,
                 created_at, review_status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Simulated",
                    scenario,
                    "Info",
                    "Simulated placeholder only. No network traffic "
                    "was generated and no AI model ran.",
                    datetime.now().isoformat(timespec="seconds"),
                    "Needs review",
                ),
            )

        flash(
            "Simulated placeholder event saved. "
            "No network traffic was generated.",
            "success",
        )

        return redirect(url_for("demo_mode"))

    with get_db() as db:
        events = db.execute(
            """
            SELECT * FROM events
            WHERE source_type = 'Simulated'
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    return render_template(
        "demo_mode.html",
        events=events,
    )


# --------------------------------------------------
# THREAT FINDINGS
# --------------------------------------------------

@app.route("/findings", methods=["GET", "POST"])
def findings():
    if request.method == "POST":
        event_id = request.form.get("event_id", type=int)

        if event_id:
            with get_db() as db:
                db.execute(
                    """
                    UPDATE events
                    SET review_status = 'Reviewed'
                    WHERE id = ?
                    """,
                    (event_id,),
                )

            flash("Event marked as reviewed.", "success")

        return redirect(url_for("findings"))

    with get_db() as db:
        events = db.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT 1000
            """
        ).fetchall()

        ai_findings_count = db.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE source_type = 'AI Prediction'
            """
        ).fetchone()[0]

    return render_template(
        "findings.html",
        events=events,
        ai_findings_count=ai_findings_count,
    )


# --------------------------------------------------
# PERFORMANCE LAB
# --------------------------------------------------



@app.route("/performance")
def performance():
    import json

    # Existing AI model comparison report
    comparison_path = BASE_DIR / "reports" / "model_comparison.json"
    comparison = None
    comparison_error = None

    if comparison_path.exists():
        try:
            with comparison_path.open("r", encoding="utf-8") as file:
                comparison = json.load(file)
        except (OSError, json.JSONDecodeError):
            app.logger.exception("Could not load model comparison report")
            comparison_error = "Comparison report could not be read."
    else:
        comparison_error = (
            "No model comparison report found. "
            "Run compare_models.py first."
        )

    # PDC benchmark results are stored separately
    pdc_path = BASE_DIR / "reports" / "pdc_benchmarks.json"
    pdc_benchmarks = None
    pdc_error = None

    if pdc_path.exists():
        try:
            with pdc_path.open("r", encoding="utf-8") as file:
                pdc_benchmarks = json.load(file)

            if not isinstance(pdc_benchmarks, dict):
                raise ValueError("PDC benchmark report must be a JSON object.")

        except (OSError, json.JSONDecodeError, ValueError):
            app.logger.exception("Could not load PDC benchmark report")
            pdc_benchmarks = None
            pdc_error = "PDC benchmark report could not be read."
    else:
        pdc_error = (
            "No PDC benchmark report found. "
            "Check reports/pdc_benchmarks.json."
        )

    return render_template(
        "performance.html",
        comparison=comparison,
        comparison_error=comparison_error,
        pdc_benchmarks=pdc_benchmarks,
        pdc_error=pdc_error,
    )


# --------------------------------------------------
# REPORTS & HISTORY
# --------------------------------------------------

@app.route("/history")
def history():
    with get_db() as db:
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()

        events = db.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT 25
            """
        ).fetchall()

    return render_template(
        "history.html",
        scans=scans,
        events=events,
    )


# --------------------------------------------------
# SETTINGS
# --------------------------------------------------


@app.route("/settings")
def settings():
    import json

    model_exists = MODEL_PATH.exists()
    pdc_report_path = BASE_DIR / "reports" / "pdc_benchmarks.json"
    pdc_report_valid = False

    if pdc_report_path.exists():
        try:
            with pdc_report_path.open("r", encoding="utf-8") as file:
                pdc_data = json.load(file)

            pdc_report_valid = (
                isinstance(pdc_data, dict)
                and isinstance(pdc_data.get("openmp_scalability"), list)
                and isinstance(pdc_data.get("mpi_scalability"), list)
                and isinstance(pdc_data.get("pthreads"), dict)
            )
        except (OSError, json.JSONDecodeError):
            app.logger.exception("Could not validate PDC report")

    checks = [
        (
            "Flask web app",
            True,
            "The local web application is running.",
        ),
        (
            "SQLite database",
            DB_PATH.exists(),
            "Stores local scan and event history.",
        ),
        (
            "Trained AI model",
            model_exists,
            (
                "Model file found. Predictions use the configured baseline."
                if model_exists
                else "Model not found. Run train_model.py first."
            ),
        ),
        (
            "Live packet capture",
            False,
            "Capture is not currently verified as active. Configure and test an authorized network interface first.",
        ),
        (
            "PDC benchmarks",
            pdc_report_valid,
            (
                "Recorded OpenMP, Pthreads, and MPI benchmark results are available."
                if pdc_report_valid
                else "PDC benchmark report is missing or invalid. Check reports/pdc_benchmarks.json."
            ),
        ),
    ]

    return render_template(
        "settings.html",
        checks=checks,
        db_path=str(DB_PATH),
    )



# --------------------------------------------------
# FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def too_large(_error):
    flash(
        f"File exceeds the {MAX_UPLOAD_MB} MB upload limit.",
        "error",
    )
    return redirect(url_for("analysis"))


# --------------------------------------------------
# START LOCAL SERVER
# --------------------------------------------------

if __name__ == "__main__":
    # Local-only development server.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
