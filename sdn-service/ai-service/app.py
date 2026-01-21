import flask
from flask import request, jsonify
import numpy as np
import tensorflow as tf
import joblib
import json
import logging
import os
from datetime import datetime
from feature_extractor import FlowFeatureExtractor

# =====================================================
# 1. LOGGING CONFIGURATION
# =====================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = flask.Flask(__name__)

# =====================================================
# 2. CONSTANTS & PATHS
# =====================================================
MODEL_DL_PATH = "model_v2.tflite"
MODEL_RF_PATH = "model_rf.pkl"
SCALER_PATH   = "scaler_insdn.json"

TIMESTEPS = 5
CONFIDENCE_THRESHOLD = 0.60

SIEM_LOG_FILE = "/var/log/siem_events.log"

# =====================================================
# 3. GLOBAL STATE
# =====================================================
extractor = FlowFeatureExtractor()

interpreter = None
rf_model = None
scaler_stats = None
input_details = None
output_details = None

flow_buffers = {}

# =====================================================
# 4. SIEM EVENT WRITER (CORE ADDITION)
# =====================================================
def write_siem_event(src_ip, dst_ip, attack_type, confidence, action):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "attack_type": attack_type,
        "confidence": round(confidence, 3),
        "action": action,
        "severity": "HIGH",
        "detected_by": "AI-IDS"
    }

    try:
        with open(SIEM_LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        logging.info("🧾 SIEM event written")
    except Exception as e:
        logging.error("❌ Failed to write SIEM event: %s", e)

# =====================================================
# 5. AI RESPONSE PRINTER (DEBUG ONLY)
# =====================================================
def print_ai_response(flow_id, src_ip, prediction, confidence, model_used, reason):
    print("\n" + "=" * 55, flush=True)
    print("🤖 AI RESPONSE", flush=True)
    print("=" * 55, flush=True)
    print(f"Flow ID    : {flow_id}", flush=True)
    print(f"Source IP : {src_ip}", flush=True)
    print(f"Prediction: {'ATTACK 🚨' if prediction == 1 else 'NORMAL ✅'}", flush=True)
    print(f"Confidence: {confidence:.2f}", flush=True)
    print(f"Model Used: {model_used}", flush=True)
    if prediction == 1:
        print(f"Reason    : {reason}", flush=True)
    print("=" * 55 + "\n", flush=True)

# =====================================================
# 6. LOAD MODELS & SCALER
# =====================================================
def load_system():
    global interpreter, rf_model, scaler_stats, input_details, output_details

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Scaler file missing")

    with open(SCALER_PATH) as f:
        scaler_stats = json.load(f)
    logging.info("✅ Scaler loaded")

    try:
        interpreter = tf.lite.Interpreter(model_path=MODEL_DL_PATH)
        interpreter.allocate_tensors()
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
        logging.info("✅ CNN-BiLSTM loaded")
    except Exception as e:
        logging.error("❌ DL Model failed: %s", e)
        interpreter = None

    try:
        rf_model = joblib.load(MODEL_RF_PATH)
        logging.info("✅ Random Forest loaded")
    except Exception as e:
        logging.warning("⚠️ RF Model disabled: %s", e)
        rf_model = None

load_system()

# =====================================================
# 7. HEALTH CHECK
# =====================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "active",
        "dl_model": interpreter is not None,
        "rf_model": rf_model is not None
    })

# =====================================================
# 8. MAIN INFERENCE ENDPOINT
# =====================================================
@app.route("/analyze_flow", methods=["POST"])
def analyze_flow():
    logging.info("📥 /analyze_flow request received")

    try:
        if not request.json:
            return jsonify({"error": "Missing JSON body"}), 400

        flow_id = request.json.get("flow_id", "unknown_flow")
        src_ip  = request.json.get("src_ip", "UNKNOWN")
        dst_ip  = request.json.get("dst_ip", "UNKNOWN")

        # ---------------- FEATURE EXTRACTION ----------------
        feature_vector = extractor.build_vector(request.json)

        mins   = np.array(scaler_stats["min"], dtype=np.float32)
        ranges = np.array(scaler_stats["range"], dtype=np.float32)
        ranges[ranges == 0] = 1.0
        scaled_vector = (feature_vector - mins) / ranges

        # ---------------- TEMPORAL BUFFER ----------------
        flow_buffers.setdefault(flow_id, [])
        flow_buffers[flow_id].append(scaled_vector[0])

        if len(flow_buffers[flow_id]) > TIMESTEPS:
            flow_buffers[flow_id].pop(0)

        curr = np.array(flow_buffers[flow_id])
        if len(curr) < TIMESTEPS:
            padding = np.zeros((TIMESTEPS - len(curr), curr.shape[1]), dtype=np.float32)
            lstm_input = np.vstack([padding, curr])
        else:
            lstm_input = curr

        # ---------------- INFERENCE ----------------
        prediction = 0
        confidence = 0.0
        model_used = "None"
        reason = "N/A"
        dl_success = False

        if interpreter is not None:
            inp = np.expand_dims(lstm_input, axis=0).astype(np.float32)
            interpreter.set_tensor(input_details[0]["index"], inp)
            interpreter.invoke()
            output = interpreter.get_tensor(output_details[0]["index"])[0]

            class_idx = int(np.argmax(output))
            confidence = float(output[class_idx])

            if confidence >= CONFIDENCE_THRESHOLD:
                prediction = class_idx
                model_used = "CNN-BiLSTM"
                dl_success = True

        if not dl_success and rf_model is not None:
            flat = scaled_vector.reshape(1, -1)
            prediction = int(rf_model.predict(flat)[0])
            try:
                confidence = float(max(rf_model.predict_proba(flat)[0]))
            except Exception:
                confidence = 1.0
            model_used = "RandomForest"

        # ---------------- MITIGATION DECISION ----------------
        mitigation = None

        if prediction == 1:
            pkt_rate = feature_vector[0][6]
            syn_cnt  = feature_vector[0][14]

            if pkt_rate > 1000:
                reason = "High Packet Rate (DoS)"
            elif syn_cnt > 50:
                reason = "SYN Flood"
            else:
                reason = "Malicious Flow Pattern"

            mitigation = {
                "action": "BLOCK",
                "target": src_ip,
                "priority": 100,
                "idle_timeout": 300,
                "hard_timeout": 600
            }

            # 🔥 SIEM EVENT (REAL AI RESPONSE)
            write_siem_event(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=reason,
                confidence=confidence,
                action="BLOCK"
            )

        # ---------------- DEBUG PRINT ----------------
        print_ai_response(
            flow_id=flow_id,
            src_ip=src_ip,
            prediction=prediction,
            confidence=confidence,
            model_used=model_used,
            reason=reason
        )

        return jsonify({
            "flow_id": flow_id,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "model_used": model_used,
            "reason": reason,
            "mitigation": mitigation,
            "status": "success"
        })

    except Exception as e:
        logging.error("❌ Processing error: %s", e)
        return jsonify({"error": "Internal Error", "details": str(e)}), 500

# =====================================================
# 9. RUN SERVER
# =====================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

