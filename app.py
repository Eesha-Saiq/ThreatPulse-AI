from pathlib import Path
import csv
from io import BytesIO, StringIO
import sqlite3
from datetime import datetime
import threading
import time
from collections import deque
import joblib
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
)

from scapy.all import sniff, IP, IPv6, TCP, UDP, conf
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
)
# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "datasets" / "uploads"
MODEL_DIR = BASE_DIR / "models"
LIVE_MODEL_PATH = MODEL_DIR / "threatpulse_live_model.joblib"
LIVE_MODEL_CACHE = None

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

def load_live_model():
    """Load and cache the separately trained 19-feature Live AI model."""
    global LIVE_MODEL_CACHE

    if LIVE_MODEL_CACHE is not None:
        return LIVE_MODEL_CACHE

    if not LIVE_MODEL_PATH.exists():
        raise FileNotFoundError(
            "Live AI model not found. Run train_live_model.py first."
        )

    model = joblib.load(LIVE_MODEL_PATH)

    if not hasattr(model, "feature_names_in_"):
        raise ValueError(
            "Live AI model does not contain a feature schema."
        )

    if len(model.feature_names_in_) != 19:
        raise ValueError(
            "Live AI model must contain exactly 19 features."
        )

    LIVE_MODEL_CACHE = model
    return LIVE_MODEL_CACHE


def _build_live_model_features(flow):
    """
    Build the exact 19-feature input required by the
    separately trained Live AI model.

    Dataset Analysis continues using the original 43-feature model.
    """

    model = load_live_model()
    expected_columns = list(model.feature_names_in_)

    features = {
        column: float("nan")
        for column in expected_columns
    }

    observed_features = []
    approximate_features = []

    def set_observed(name, value):
        if name in features and value is not None:
            features[name] = value
            observed_features.append(name)

    def set_approximate(name, value):
        if name in features and value is not None:
            features[name] = value
            approximate_features.append(name)

    # 1. Categorical features
    source_port = flow.get("forward_source_port")
    destination_port = flow.get("forward_destination_port")

    set_observed(
        "sport",
        str(source_port) if source_port is not None else None
    )

    set_observed(
        "dsport",
        str(destination_port) if destination_port is not None else None
    )

    protocol = flow.get("protocol")

    if protocol is not None:
        set_observed("proto", str(protocol).lower())

    tcp_state = flow.get("tcp_state")

    if tcp_state is not None:
        set_approximate("state", str(tcp_state).upper())

    # 2. Flow duration and directional statistics
    duration = flow.get("duration")

    set_observed("dur", duration)

    forward_bytes = flow.get("forward_bytes")
    reverse_bytes = flow.get("reverse_bytes")

    set_observed("sbytes", forward_bytes)
    set_observed("dbytes", reverse_bytes)

    set_observed("Spkts", flow.get("forward_packets"))
    set_observed("Dpkts", flow.get("reverse_packets"))

    # 3. Directional load in bits per second
    if duration is not None and duration > 0:

        if forward_bytes is not None:
            set_approximate(
                "Sload",
                float(forward_bytes) * 8.0 / float(duration)
            )

        if reverse_bytes is not None:
            set_approximate(
                "Dload",
                float(reverse_bytes) * 8.0 / float(duration)
            )

    # 4. TTL and TCP window values
    set_observed("sttl", flow.get("sttl"))
    set_observed("dttl", flow.get("dttl"))


    # 5. Average directional packet sizes
    set_observed("smeansz", flow.get("smeansz"))
    set_observed("dmeansz", flow.get("dmeansz"))

    # 6. TCP handshake timing values (seconds)
    set_approximate("synack", flow.get("synack"))
    set_approximate("ackdat", flow.get("ackdat"))
    set_approximate("tcprtt", flow.get("tcprtt"))

    # 7. Same IP and same port indicator
    source_ip = flow.get("forward_source_ip")
    destination_ip = flow.get("forward_destination_ip")

    if (
        source_ip is not None
        and destination_ip is not None
        and source_port is not None
        and destination_port is not None
    ):
        same_ip_and_port = (
            source_ip == destination_ip
            and source_port == destination_port
        )

        set_observed(
            "is_sm_ips_ports",
            int(same_ip_and_port)
        )

    # 8. Identify unavailable features
    unavailable_features = [
        column
        for column in expected_columns
        if column not in observed_features
        and column not in approximate_features
    ]

    # 9. Build DataFrame in exact model feature order
    feature_frame = pd.DataFrame(
        [features],
        columns=expected_columns
    )

    categorical_columns = {
        "sport",
        "dsport",
        "proto",
        "state",
    }

    numeric_columns = [
        column
        for column in expected_columns
        if column not in categorical_columns
    ]

    for column in numeric_columns:
        feature_frame[column] = pd.to_numeric(
            feature_frame[column],
            errors="coerce"
        )

    feature_frame[numeric_columns] = (
        feature_frame[numeric_columns]
        .replace([float("inf"), float("-inf")], float("nan"))
    )

    # 10. Feature quality report
    available_count = (
        len(observed_features)
        + len(approximate_features)
    )

    coverage = (
        available_count / len(expected_columns) * 100
        if expected_columns
        else 0.0
    )

    quality = {
        "total_features": len(expected_columns),
        "observed_count": len(observed_features),
        "approximate_count": len(approximate_features),
        "unavailable_count": len(unavailable_features),
        "coverage_percent": round(coverage, 2),
        "observed_features": observed_features,
        "approximate_features": approximate_features,
        "unavailable_features": unavailable_features,

        # Keep disabled until live predictions are independently validated.
        "prediction_ready": False,
    }

    return feature_frame, quality





def predict_dataset(frame):
    """
    Predict normal or potential attack labels for a CSV dataset.
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

    # Match uploaded dataset to model training features.
    features = features.reindex(columns=expected_columns)

    # Convert numeric features safely.
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

def predict_live_flow(flow):
    """
    Generate a prediction for one live network flow
    using the separate 19-feature Live AI model.
    """

    model = load_live_model()

    feature_frame, quality = _build_live_model_features(flow)

    prediction = int(model.predict(feature_frame)[0])

    probabilities = model.predict_proba(feature_frame)[0]
    classes = list(model.classes_)

    attack_probability = None

    if 1 in classes:
        attack_index = classes.index(1)
        attack_probability = round(
            float(probabilities[attack_index]) * 100,
            2
        )

    return {
        "prediction": prediction,
        "label": (
            "Potential Attack"
            if prediction == 1
            else "Normal"
        ),
        "attack_probability": attack_probability,
        "feature_quality": quality,
        "model": "Live AI - 19 Features",
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
    try:
        capture_ready = bool(list(conf.ifaces.values()))
    except Exception:
        capture_ready = False

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
        capture_ready=capture_ready,
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
LIVE_MONITOR_AI_ALERTS = deque(maxlen=100)
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

        LIVE_MONITOR_AI_ALERTS.append({
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
    """Aggregate bidirectional flow statistics and TCP handshake metadata."""

    key = _live_flow_key(
        record["source_ip"],
        record["destination_ip"],
        record["protocol"],
        record["source_port"],
        record["destination_port"],
    )

    source_ip = str(record["source_ip"])
    destination_ip = str(record["destination_ip"])
    source_port = int(record["source_port"] or 0)
    destination_port = int(record["destination_port"] or 0)

    packet_length = max(0, int(packet_length))
    current_timestamp = time.time()

    tcp_flags = record.get("tcp_flags", {})

    packet_ttl = record.get("ttl")
    tcp_window = record.get("tcp_window")
    tcp_seq = record.get("tcp_seq")
    tcp_ack_number = record.get("tcp_ack_number")

    with LIVE_MONITOR_LOCK:

        if not LIVE_MONITOR_STATE["active"]:
            return

        flow = LIVE_MONITOR_FLOWS.get(key)

        # Create a new flow.
        if flow is None:

            if len(LIVE_MONITOR_FLOWS) >= LIVE_MONITOR_FLOW_LIMIT:
                oldest_key = next(iter(LIVE_MONITOR_FLOWS))
                LIVE_MONITOR_FLOWS.pop(oldest_key, None)

            flow = {
                "protocol": record["protocol"],
                "ai_prediction": None,
                "ai_prediction_time": None,
                "ai_prediction_status": "pending",

                "endpoint_a": f"{source_ip}:{source_port}",
                "endpoint_b": f"{destination_ip}:{destination_port}",

                "packets": 0,
                "bytes": 0,

                "forward_packets": 0,
                "reverse_packets": 0,

                "forward_bytes": 0,
                "reverse_bytes": 0,

                "forward_source_ip": source_ip,
                "forward_source_port": source_port,
                "forward_destination_ip": destination_ip,
                "forward_destination_port": destination_port,

                "first_seen": record["time"],
                "last_seen": record["time"],

                "_first_seen_ts": current_timestamp,
                "_last_seen_ts": current_timestamp,

                "_last_forward_ts": None,
                "_last_reverse_ts": None,

                "duration": 0.0,

                "iat_sum": 0.0,
                "iat_count": 0,

                "forward_iat_sum": 0.0,
                "forward_iat_count": 0,

                "reverse_iat_sum": 0.0,
                "reverse_iat_count": 0,

                # Directional jitter tracking.
                "_previous_forward_iat": None,
                "_previous_reverse_iat": None,

                "forward_jitter_sum": 0.0,
                "forward_jitter_count": 0,

                "reverse_jitter_sum": 0.0,
                "reverse_jitter_count": 0,

                "min_packet_size": packet_length,
                "max_packet_size": packet_length,

                "smeansz": 0.0,
                "dmeansz": 0.0,

                "sttl": None,
                "dttl": None,

                "swin": None,
                "dwin": None,

                "stcpb": None,
                "dtcpb": None,

                # TCP handshake tracking.
                "_syn_timestamp": None,
                "_syn_sequence": None,

                "_synack_timestamp": None,
                "_synack_sequence": None,

                "synack": None,
                "ackdat": None,
                "tcprtt": None,

                "tcp_syn_count": 0,
                "tcp_ack_count": 0,
                "tcp_fin_count": 0,
                "tcp_rst_count": 0,
                "tcp_psh_count": 0,
                "tcp_urg_count": 0,

                "tcp_state": "INT",
            }

            LIVE_MONITOR_FLOWS[key] = flow

        # Identify packet direction.
        is_forward = (
            source_ip == flow["forward_source_ip"]
            and source_port == flow["forward_source_port"]
            and destination_ip == flow["forward_destination_ip"]
            and destination_port == flow["forward_destination_port"]
        )

        # Store first observed metadata per direction.
        if is_forward:

            if flow["sttl"] is None and packet_ttl is not None:
                flow["sttl"] = int(packet_ttl)

            if flow["swin"] is None and tcp_window is not None:
                flow["swin"] = int(tcp_window)

            if flow["stcpb"] is None and tcp_seq is not None:
                flow["stcpb"] = int(tcp_seq)

        else:

            if flow["dttl"] is None and packet_ttl is not None:
                flow["dttl"] = int(packet_ttl)

            if flow["dwin"] is None and tcp_window is not None:
                flow["dwin"] = int(tcp_window)

            if flow["dtcpb"] is None and tcp_seq is not None:
                flow["dtcpb"] = int(tcp_seq)

        # Calculate overall inter-arrival time.
        if flow["packets"] > 0:

            inter_arrival = max(
                0.0,
                current_timestamp - flow["_last_seen_ts"]
            )

            flow["iat_sum"] += inter_arrival
            flow["iat_count"] += 1

        # Calculate directional IAT and jitter.
        if is_forward:

            if flow["_last_forward_ts"] is not None:

                current_iat = max(
                    0.0,
                    current_timestamp - flow["_last_forward_ts"]
                )

                flow["forward_iat_sum"] += current_iat
                flow["forward_iat_count"] += 1

                previous_iat = flow["_previous_forward_iat"]

                if previous_iat is not None:
                    flow["forward_jitter_sum"] += abs(
                        current_iat - previous_iat
                    )

                    flow["forward_jitter_count"] += 1

                flow["_previous_forward_iat"] = current_iat

            flow["_last_forward_ts"] = current_timestamp

        else:

            if flow["_last_reverse_ts"] is not None:

                current_iat = max(
                    0.0,
                    current_timestamp - flow["_last_reverse_ts"]
                )

                flow["reverse_iat_sum"] += current_iat
                flow["reverse_iat_count"] += 1

                previous_iat = flow["_previous_reverse_iat"]

                if previous_iat is not None:
                    flow["reverse_jitter_sum"] += abs(
                        current_iat - previous_iat
                    )

                    flow["reverse_jitter_count"] += 1

                flow["_previous_reverse_iat"] = current_iat

            flow["_last_reverse_ts"] = current_timestamp

        # Update total packet and byte counts.
        flow["packets"] += 1
        flow["bytes"] += packet_length

        # Update packet size statistics.
        flow["min_packet_size"] = min(
            flow["min_packet_size"],
            packet_length
        )

        flow["max_packet_size"] = max(
            flow["max_packet_size"],
            packet_length
        )

        # Update timestamps and duration.
        flow["last_seen"] = record["time"]
        flow["_last_seen_ts"] = current_timestamp

        flow["duration"] = max(
            0.0,
            current_timestamp - flow["_first_seen_ts"]
        )

        # Update directional statistics.
        if is_forward:
            flow["forward_packets"] += 1
            flow["forward_bytes"] += packet_length

        else:
            flow["reverse_packets"] += 1
            flow["reverse_bytes"] += packet_length

        # Calculate average packet sizes.
        flow["smeansz"] = (
            flow["forward_bytes"] / flow["forward_packets"]
            if flow["forward_packets"] > 0
            else 0.0
        )

        flow["dmeansz"] = (
            flow["reverse_bytes"] / flow["reverse_packets"]
            if flow["reverse_packets"] > 0
            else 0.0
        )

        # Count TCP flags and track handshake.
        if record["protocol"] == "TCP":

            syn = tcp_flags.get("syn", False)
            ack = tcp_flags.get("ack", False)

            if syn:
                flow["tcp_syn_count"] += 1

            if ack:
                flow["tcp_ack_count"] += 1

            if tcp_flags.get("fin", False):
                flow["tcp_fin_count"] += 1

            if tcp_flags.get("rst", False):
                flow["tcp_rst_count"] += 1

            if tcp_flags.get("psh", False):
                flow["tcp_psh_count"] += 1

            if tcp_flags.get("urg", False):
                flow["tcp_urg_count"] += 1

            # Step 1: Initial SYN from forward direction.
            if (
                is_forward
                and syn
                and not ack
                and tcp_seq is not None
                and flow["_syn_timestamp"] is None
            ):
                flow["_syn_timestamp"] = current_timestamp
                flow["_syn_sequence"] = int(tcp_seq)

            # Step 2: Matching SYN-ACK from reverse direction.
            elif (
                not is_forward
                and syn
                and ack
                and tcp_seq is not None
                and tcp_ack_number is not None
                and flow["_syn_timestamp"] is not None
                and flow["_synack_timestamp"] is None
            ):
                expected_ack = (
                    int(flow["_syn_sequence"]) + 1
                ) % (2 ** 32)

                if int(tcp_ack_number) == expected_ack:

                    flow["_synack_timestamp"] = current_timestamp
                    flow["_synack_sequence"] = int(tcp_seq)

                    flow["synack"] = max(
                        0.0,
                        current_timestamp - flow["_syn_timestamp"]
                    )

            # Step 3: Matching final ACK from forward direction.
            elif (
                is_forward
                and ack
                and not syn
                and tcp_ack_number is not None
                and flow["_synack_timestamp"] is not None
                and flow["ackdat"] is None
            ):
                expected_ack = (
                    int(flow["_synack_sequence"]) + 1
                ) % (2 ** 32)

                if int(tcp_ack_number) == expected_ack:

                    flow["ackdat"] = max(
                        0.0,
                        current_timestamp - flow["_synack_timestamp"]
                    )

                    flow["tcprtt"] = (
                        flow["synack"] + flow["ackdat"]
                    )

            # Determine approximate TCP connection state.
            if flow["tcp_rst_count"] > 0:
                flow["tcp_state"] = "RST"

            elif flow["tcp_fin_count"] > 0:
                flow["tcp_state"] = "FIN"

            elif (
                flow["tcp_syn_count"] > 0
                and flow["tcp_ack_count"] > 0
            ):
                flow["tcp_state"] = "CON"

            elif flow["tcp_syn_count"] > 0:
                flow["tcp_state"] = "REQ"

            elif flow["tcp_ack_count"] > 0:
                flow["tcp_state"] = "ACC"

            else:
                flow["tcp_state"] = "INT"
    return key
def _maybe_predict_live_flow(flow_key):
    """
    Run experimental AI prediction for mature flows
    in a background thread without blocking packet capture.
    """

    with LIVE_MONITOR_LOCK:

        if not LIVE_MONITOR_STATE["active"]:
            return

        flow = LIVE_MONITOR_FLOWS.get(flow_key)

        if flow is None:
            return

        if flow.get("ai_prediction_status") != "pending":
            return

        # Require sufficient bidirectional activity.
        if flow.get("packets", 0) < 20:
            return

        if flow.get("reverse_packets", 0) < 5:
            return

        # Prevent duplicate predictions.
        flow["ai_prediction_status"] = "processing"

        flow_snapshot = dict(flow)

    def prediction_worker():

        try:
            # Run model inference outside the packet capture thread.
            result = predict_live_flow(flow_snapshot)

        except Exception:

            with LIVE_MONITOR_LOCK:

                flow = LIVE_MONITOR_FLOWS.get(flow_key)

                if flow is not None:
                    flow["ai_prediction_status"] = "error"

            app.logger.exception(
                "Experimental Live AI prediction failed."
            )
            return

        with LIVE_MONITOR_LOCK:

            flow = LIVE_MONITOR_FLOWS.get(flow_key)

            if flow is None:
                return

            flow["ai_prediction"] = result

            flow["ai_prediction_time"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            flow["ai_prediction_status"] = "experimental"

            # Record AI alert separately from heuristic alerts.
            if result.get("prediction") == 1:

                probability = result.get(
                    "attack_probability"
                )

                LIVE_MONITOR_ALERTS.appendleft({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "severity": "warning",
                    "type": "Experimental AI Potential Attack",
                    "source_ip": flow.get("forward_source_ip", "Unknown"),
                    "destination_ip": flow.get(
                         "forward_destination_ip", "Unknown"
),
                    "message": (
                        "Experimental AI model flagged this flow. "
                        f"Attack probability: {probability}%"
                        if probability is not None
                        else "Experimental AI model flagged this flow."
                    ),
                    "classification": "ai_model",
                })

    try:
        worker = threading.Thread(
            target=prediction_worker,
            daemon=True,
            name="Live-AI-Prediction"
        )

        worker.start()

    except Exception:

        with LIVE_MONITOR_LOCK:

            flow = LIVE_MONITOR_FLOWS.get(flow_key)

            if flow is not None:
                flow["ai_prediction_status"] = "error"

        app.logger.exception(
            "Could not start Live AI prediction worker."
        )

def _live_packet_metadata(packet):
    """Extract network headers and TCP metadata without storing payloads."""

    try:
        # Extract IP addresses and TTL.
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            ttl = int(packet[IP].ttl)

        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
            ttl = int(packet[IPv6].hlim)

        else:
            return

        protocol = "Other"
        source_port = None
        destination_port = None

        tcp_window = None
        tcp_seq = None
        tcp_ack_number = None

        record_flags = {
            "syn": False,
            "ack": False,
            "fin": False,
            "rst": False,
            "psh": False,
            "urg": False,
        }

        # Extract TCP metadata.
        if TCP in packet:
            protocol = "TCP"

            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)

            tcp_window = int(packet[TCP].window)
            tcp_seq = int(packet[TCP].seq)
            tcp_ack_number = int(packet[TCP].ack)

            tcp_flags = int(packet[TCP].flags)

            record_flags = {
                "syn": bool(tcp_flags & 0x02),
                "ack": bool(tcp_flags & 0x10),
                "fin": bool(tcp_flags & 0x01),
                "rst": bool(tcp_flags & 0x04),
                "psh": bool(tcp_flags & 0x08),
                "urg": bool(tcp_flags & 0x20),
            }

        # Extract UDP metadata.
        elif UDP in packet:
            protocol = "UDP"

            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

        # Create packet metadata record.
        record = {
            "time": datetime.now().strftime("%H:%M:%S"),

            "source_ip": str(source_ip),
            "destination_ip": str(destination_ip),

            "protocol": protocol,

            "source_port": source_port,
            "destination_port": destination_port,

            "ttl": ttl,
            "tcp_window": tcp_window,

            "tcp_seq": tcp_seq,
            "tcp_ack_number": tcp_ack_number,

            "tcp_flags": record_flags,
        }

        # Update flow statistics and retrieve flow key.
        flow_key = _update_live_flow(record, len(packet))

        # Trigger experimental AI prediction for mature flows.
        if flow_key is not None:
            _maybe_predict_live_flow(flow_key)

        # Keep heuristic alerts separate from AI predictions.
        _record_live_heuristic_alert(record, None)

        # Update live monitor counters.
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
        app.logger.debug(
            "Skipped a packet that could not be parsed.",
            exc_info=True
        )


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
        LIVE_MONITOR_ALERTS.clear()
        LIVE_MONITOR_AI_ALERTS.clear()
        LIVE_MONITOR_RECENT_ACTIVITY.clear()
        LIVE_MONITOR_ALERTED_FLOWS.clear()
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

            "alerts": (
    list(LIVE_MONITOR_ALERTS)
    + list(LIVE_MONITOR_AI_ALERTS)
),

            "ai_predictions_enabled": LIVE_MODEL_PATH.exists(),
            "ai_prediction_mode": "experimental",
            "ai_predictions_validated": False,
        }

    return jsonify({
        "ok": True,
        **state
    })


# --------------------------------------------------
# DEMO MODE
# --------------------------------------------------

@app.route("/demo-mode", methods=["GET", "POST"])
def demo_mode():

    scenarios = {
        "normal": {
            "name": "Normal Traffic Simulation",
            "severity": "Info",
            "reason": (
                "SIMULATED: Normal network activity. "
                "No real traffic was generated."
            ),
        },
        "port_scan": {
            "name": "Port Scan Simulation",
            "severity": "Medium",
            "reason": (
                "SIMULATED: Multiple connection attempts "
                "to different ports detected in the test scenario."
            ),
        },
        "dos": {
            "name": "DoS Pattern Simulation",
            "severity": "High",
            "reason": (
                "SIMULATED: High-volume traffic pattern "
                "representing a denial-of-service scenario."
            ),
        },
        "brute_force": {
            "name": "Brute Force Simulation",
            "severity": "High",
            "reason": (
                "SIMULATED: Repeated failed login attempts "
                "representing a brute-force scenario."
            ),
        },
        "suspicious": {
            "name": "Suspicious Traffic Simulation",
            "severity": "Medium",
            "reason": (
                "SIMULATED: Unusual network activity "
                "representing a suspicious traffic scenario."
            ),
        },
    }

    if request.method == "POST":

        scenario_key = request.form.get("scenario", "normal")
        selected = scenarios.get(scenario_key)

        if selected is None:
            flash("Invalid simulation scenario selected.", "error")
            return redirect(url_for("demo_mode"))

        with get_db() as db:
            db.execute(
                """
                INSERT INTO events
                (
                    source_type,
                    event_type,
                    severity,
                    reason,
                    created_at,
                    review_status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Simulated",
                    selected["name"],
                    selected["severity"],
                    selected["reason"],
                    datetime.now().isoformat(timespec="seconds"),
                    "Needs review",
                ),
            )

        flash(
            f'{selected["name"]} completed. '
            "A simulated event was saved in Threat Findings.",
            "success",
        )

        return redirect(url_for("demo_mode"))

    with get_db() as db:
        events = db.execute(
            """
            SELECT * FROM events
            WHERE source_type = 'Simulated'
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

    return render_template(
        "demo_mode.html",
        events=events,
        scenarios=scenarios,
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
@app.route("/export/pdf")
def export_pdf():
    buffer = BytesIO()

    with get_db() as db:
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()

        events = db.execute(
            "SELECT * FROM events ORDER BY id DESC"
        ).fetchall()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=25,
        leftMargin=25,
        topMargin=30,
        bottomMargin=30,
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(
        "ThreatPulse AI - Security Report",
        styles["Title"]
    ))

    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 18))

    elements.append(Paragraph("Dataset Scans", styles["Heading2"]))

    scan_data = [[
        "ID", "Filename", "Status", "Rows",
        "Columns", "Created", "Message"
    ]]

    for scan in scans:
        scan_data.append([
            str(scan["id"]),
            str(scan["filename"]),
            str(scan["status"]),
            str(scan["row_count"]),
            str(scan["column_count"]),
            str(scan["created_at"]),
            Paragraph(str(scan["message"] or ""), styles["BodyText"]),
        ])

    scan_table = Table(
        scan_data,
        repeatRows=1,
        colWidths=[25, 100, 55, 40, 45, 100, 180],
    )

    scan_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263449")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#EDF1F5")]),
    ]))

    elements.append(scan_table)
    elements.append(Spacer(1, 22))

    elements.append(Paragraph("Recent Security Events", styles["Heading2"]))

    event_data = [[
        "ID", "Event", "Source", "Severity",
        "Reason", "Created", "Review Status"
    ]]

    for event in events:
        event_data.append([
            str(event["id"]),
            str(event["event_type"]),
            str(event["source_type"]),
            str(event["severity"]),
            Paragraph(str(event["reason"] or ""), styles["BodyText"]),
            str(event["created_at"]),
            str(event["review_status"]),
        ])

    event_table = Table(
        event_data,
        repeatRows=1,
        colWidths=[25, 100, 65, 50, 180, 100, 65],
    )

    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263449")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#EDF1F5")]),
    ]))

    elements.append(event_table)

    document.build(elements)
    buffer.seek(0)

    filename = f"ThreatPulse_Report_{datetime.now():%Y%m%d_%H%M%S}.pdf"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )

@app.route("/export/csv")
def export_csv():
    output = StringIO()
    writer = csv.writer(output)

    def safe_value(value):
        value = "" if value is None else str(value)
        if value.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
        return value

    with get_db() as db:
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()

        events = db.execute(
            "SELECT * FROM events ORDER BY id DESC"
        ).fetchall()

    writer.writerow(["ThreatPulse AI - Security Report"])
    writer.writerow([
        "Generated At",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ])

    writer.writerow([])
    writer.writerow(["DATASET SCANS"])
    writer.writerow([
        "ID", "Filename", "Status", "Rows",
        "Columns", "Created At", "Message"
    ])

    for scan in scans:
        writer.writerow([
            safe_value(scan["id"]),
            safe_value(scan["filename"]),
            safe_value(scan["status"]),
            safe_value(scan["row_count"]),
            safe_value(scan["column_count"]),
            safe_value(scan["created_at"]),
            safe_value(scan["message"]),
        ])

    writer.writerow([])
    writer.writerow(["SECURITY EVENTS"])
    writer.writerow([
        "ID", "Event", "Source", "Severity",
        "Reason", "Created At", "Review Status"
    ])

    for event in events:
        writer.writerow([
            safe_value(event["id"]),
            safe_value(event["event_type"]),
            safe_value(event["source_type"]),
            safe_value(event["severity"]),
            safe_value(event["reason"]),
            safe_value(event["created_at"]),
            safe_value(event["review_status"]),
        ])

    csv_bytes = BytesIO(output.getvalue().encode("utf-8-sig"))
    output.close()
    csv_bytes.seek(0)

    filename = f"ThreatPulse_Report_{datetime.now():%Y%m%d_%H%M%S}.csv"

    return send_file(
        csv_bytes,
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )

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
    try:
        capture_ready = bool(list(conf.ifaces.values()))
    except Exception:
        capture_ready = False
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
            capture_ready,
            (
                "Network interfaces are available. Authorized packet capture can be started."
                if capture_ready
                else "No network interfaces are available. Check packet capture configuration."
            ),
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
