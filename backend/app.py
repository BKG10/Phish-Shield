'''
# =====================================================================
# PhishShield Backend API
# This FastAPI application serves as the backend for the PhishShield browser extension.
# It provides endpoints for phishing detection using a trained XGBoost model.
# =====================================================================

# Import required libraries
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from url_feature_extractor import URLFeatureExtractor  # Custom class to extract features from URLs

# Initialize FastAPI application
app = FastAPI()

# Enable CORS (Cross-Origin Resource Sharing) to allow requests from the browser extension
# This is necessary because the extension makes requests from a different origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, this should be restricted to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load pre-trained model components
# The scaler ensures input features are scaled consistently with training data
scaler = joblib.load("scaler.pkl")
# Load the trained XGBoost model for phishing detection
booster = xgb.Booster()
booster.load_model("xgb_model.json")

# Define the expected feature columns in correct order
# These must match the order used during model training
FEATURE_COLUMNS = [
    "URLLength", "DomainLength", "TLDLength", "NoOfImage", "NoOfJS", "NoOfCSS", 
    "NoOfSelfRef", "NoOfExternalRef", "IsHTTPS", "HasObfuscation", "HasTitle", 
    "HasDescription", "HasSubmitButton", "HasSocialNet", "HasFavicon", 
    "HasCopyrightInfo", "popUpWindow", "Iframe", "Abnormal_URL", 
    "LetterToDigitRatio", "Redirect_0", "Redirect_1"
]

# Pydantic model for input validation of direct feature input
# This ensures all required features are provided with correct types
class URLFeatures(BaseModel):
    URLLength: int
    DomainLength: int
    TLDLength: int
    NoOfImage: int
    NoOfJS: int
    NoOfCSS: int
    NoOfSelfRef: int
    NoOfExternalRef: int
    IsHTTPS: int
    HasObfuscation: int
    HasTitle: int
    HasDescription: int
    HasSubmitButton: int
    HasSocialNet: int
    HasFavicon: int
    HasCopyrightInfo: int
    popUpWindow: int
    Iframe: int
    Abnormal_URL: int
    LetterToDigitRatio: float
    Redirect_0: int
    Redirect_1: int

# Pydantic model for raw URL input
# Used when receiving just a URL that needs feature extraction
class URLInput(BaseModel):
    url: str

# Endpoint for predicting from pre-extracted features
@app.post("/predict")
def predict(features: URLFeatures):
    try:
        # Convert input features to DataFrame with correct column order
        input_df = pd.DataFrame([features.dict()], columns=FEATURE_COLUMNS)

        # Scale features using the same scaler used during training
        scaled_input = scaler.transform(input_df)

        # Create DMatrix for XGBoost prediction
        dmatrix = xgb.DMatrix(scaled_input, feature_names=FEATURE_COLUMNS)

        # Get model prediction
        pred = booster.predict(dmatrix)
        # Convert probability to binary label (0: Phishing, 1: Legitimate)
        label = int(round(pred[0]))

        return {
            "prediction": label,
            "result": "Legitimate" if label == 1 else "Phishing"
        }
    except Exception as e:
        return {"error": str(e)}

# Endpoint for predicting from raw URL
@app.post("/predict_url")
def predict_from_url(input_data: URLInput):
    try:
        # Create feature extractor instance for the input URL
        extractor = URLFeatureExtractor(input_data.url)
        # Extract all required features
        features = extractor.extract_model_features()

        # Check if feature extraction encountered any errors
        if "error" in features:
            return {"error": features["error"]}

        # Convert extracted features to DataFrame
        input_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)

        # Scale features
        scaled_input = scaler.transform(input_df)

        # Create DMatrix and predict
        dmatrix = xgb.DMatrix(scaled_input, feature_names=FEATURE_COLUMNS)
        pred = booster.predict(dmatrix)
        label = int(round(pred[0]))

        return {
            "features": features,  # Return extracted features for debugging/logging
            "prediction": label,
            "result": "Legitimate" if label == 1 else "Phishing"
        }
    except Exception as e:
        return {"error": str(e)}

# Health check endpoint
@app.get("/")
def read_root():
    return {"message": "PhishShield API is running 🚀"}
'''