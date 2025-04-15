"""
Model Predictor Module
This module implements the machine learning prediction functionality for PhishShield.
It uses a pre-trained XGBoost model to classify URLs as phishing or legitimate.
"""

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from url_feature_extractor import URLFeatureExtractor

class ModelPredictor:
    """
    A class to handle URL phishing prediction using a pre-trained XGBoost model.
    
    This class loads the trained model and scaler, and provides methods to predict
    whether a URL is phishing or legitimate based on extracted features.
    """
    
    def __init__(self, model_path="xgb_model.json", scaler_path="scaler.pkl"):
        """
        Initialize the ModelPredictor with pre-trained model and scaler.
        
        Args:
            model_path (str): Path to the XGBoost model file
            scaler_path (str): Path to the feature scaler file
        """
        # Load the feature scaler and XGBoost model
        self.scaler = joblib.load(scaler_path)
        self.booster = xgb.Booster()
        self.booster.load_model(model_path)

        # Define the expected feature columns in the correct order
        # These features are used by the model for prediction
        self.FEATURE_COLUMNS = [
            "URLLength", "DomainLength", "TLDLength", "NoOfImage", "NoOfJS", "NoOfCSS", 
            "NoOfSelfRef", "NoOfExternalRef", "IsHTTPS", "HasObfuscation", "HasTitle", 
            "HasDescription", "HasSubmitButton", "HasSocialNet", "HasFavicon", 
            "HasCopyrightInfo", "popUpWindow", "Iframe", "Abnormal_URL", 
            "LetterToDigitRatio", "Redirect_0", "Redirect_1"
        ]

    def predict_from_url(self, url):
        """
        Predict if a URL is phishing or legitimate based on its features.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Prediction results including:
                - features: Extracted URL features
                - prediction: Binary prediction (0=phishing, 1=legitimate)
                - result: Human-readable prediction result
                - error: Error message if prediction fails
        """
        try:
            # Extract features from the URL using custom extractor
            extractor = URLFeatureExtractor(url)
            features = extractor.extract_model_features()

            if "error" in features:
                return {"error": features["error"]}

            # Convert features to DataFrame to align with expected column names
            input_df = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)

            # Scale features using the pre-trained scaler
            scaled_input = self.scaler.transform(input_df)

            # Create DMatrix for XGBoost prediction
            dmatrix = xgb.DMatrix(scaled_input, feature_names=self.FEATURE_COLUMNS)
            pred = self.booster.predict(dmatrix)
            label = int(round(pred[0]))

            return {
                "features": features,
                "prediction": label,
                "result": "Legitimate" if label == 1 else "Phishing"
            }
        except Exception as e:
            return {"error": str(e)}

    def predict_from_features(self, features):
        """
        Predict if a URL is phishing or legitimate using pre-extracted features.
        
        Args:
            features (dict): Dictionary of pre-extracted URL features
            
        Returns:
            dict: Prediction results including:
                - prediction: Binary prediction (0=phishing, 1=legitimate)
                - result: Human-readable prediction result
                - error: Error message if prediction fails
        """
        try:
            # Convert features to DataFrame with feature names
            input_df = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)

            # Scale features using the pre-trained scaler
            scaled_input = self.scaler.transform(input_df)

            # Create DMatrix for XGBoost prediction
            dmatrix = xgb.DMatrix(scaled_input, feature_names=self.FEATURE_COLUMNS)

            # Get prediction from model
            pred = self.booster.predict(dmatrix)
            label = int(round(pred[0]))

            return {
                "prediction": label,
                "result": "Legitimate" if label == 1 else "Phishing"
            }
        except Exception as e:
            return {"error": str(e)} 