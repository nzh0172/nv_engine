## RUN THIS COMMAND FIRST: pip install -r requirements.txt

from flask import Flask, request, jsonify
from joblib import load
import numpy as np
import os

app = Flask(__name__)
model_path = os.path.join(os.path.dirname(__file__), "malware_classifier.joblib")
model = load(model_path)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    features = np.array(data["input"]).reshape(1, -1)
    prediction = model.predict(features)[0]
    return jsonify({"prediction": int(prediction)})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)  # Open to LAN access
