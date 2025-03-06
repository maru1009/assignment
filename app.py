import joblib
import numpy as np
import pandas as pd  
from flask import Flask, request, jsonify, render_template
from utils import extraction_section 
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

app = Flask(__name__, static_folder='static')


# Load trained models
random_forest = joblib.load("random_forest.pkl")  
decision_tree = joblib.load("decision_tree.pkl")  
sgd = joblib.load("sgd.pkl")  
extra_trees = joblib.load("extra_trees.pkl")  
ada_boost = joblib.load("ada_boost.pkl")  
ann = joblib.load("ann.pkl")  
knn = joblib.load("knn.pkl")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze_url():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Extract features
    features_df = extraction_section(url)
    
    features_df = features_df.values.reshape(1, -1)

    # Check for NaN values
    if np.isnan(features_df).any():
        return jsonify({"error": "Invalid features. Some features could not be converted to numeric values."}), 400

    predictions = {
        "RandomForest": "Okay" if int(random_forest.predict(features_df)[0]) == 1 else "Bad",
        "DecisionTree": "Okay" if int(decision_tree.predict(features_df)[0]) == 1 else "Bad",
        "SGD": "Okay" if int(sgd.predict(features_df)[0]) == 1 else "Bad",
        "ExtraTrees": "Okay" if int(extra_trees.predict(features_df)[0]) == 1 else "Bad",
        "AdaBoost": "Okay" if int(ada_boost.predict(features_df)[0]) == 1 else "Bad",
        "ANN": "Okay" if ann.predict(features_df).flatten()[0] == 1 else "Bad",
        "KNN": "Okay" if int(knn.predict(features_df)[0]) == 1 else "Bad",
    }

    return jsonify(predictions) 



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
