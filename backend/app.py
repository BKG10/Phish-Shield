"""
PhishShield Backend API
This module implements the FastAPI backend for the PhishShield phishing detection system.
It provides endpoints for URL prediction, history management, and statistics tracking.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from model_predictor import ModelPredictor
from typing import List, Dict
from datetime import datetime
from urllib.parse import urlparse
import json
import os

# Initialize FastAPI application
app = FastAPI()

# Configure CORS middleware to allow cross-origin requests
# This is essential for the frontend to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
    expose_headers=["*"],  # Expose all headers
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Initialize the machine learning model predictor
predictor = ModelPredictor()

# List of trusted domains that are automatically marked as safe
# These are well-known, reputable websites that are unlikely to be phishing sites
TRUSTED_DOMAINS = [
    'google.com',
    'openai.com',
    'chatgpt.com',
    'chat.openai.com',
    'microsoft.com',
    'github.com',
    'stackoverflow.com',
    'linkedin.com',
    'facebook.com',
    'twitter.com',
    'youtube.com',
    'amazon.com',
    'netflix.com',
    'spotify.com',
    'reddit.com',
    'wikipedia.org',
    'medium.com',
    'quora.com',
    'dropbox.com',
    'slack.com',
    'discord.com',
    'zoom.us',
    'mozilla.org',
    'apple.com',
    'adobe.com',
    'cloudflare.com'
]

# In-memory storage for scan history
# Stores the last 10 URL scans with their results
scan_history: List[Dict] = []

# Statistics storage for tracking performance metrics
stats = {
    "daily_stats": {},  # Daily statistics for URLs scanned and threats blocked
    "response_times": []  # Response time history for performance monitoring
}

def get_domain(url: str) -> str:
    """
    Extract domain from a URL string.
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: The extracted domain or original URL if parsing fails
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain and parsed_url.path:
            # Handle URLs without protocol
            domain = urlparse(f"https://{url}").netloc
        return domain
    except Exception:
        return url

def is_trusted_domain(domain: str) -> bool:
    """
    Check if a domain is in the trusted domains list.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if domain is trusted, False otherwise
    """
    return any(trusted_domain in domain for trusted_domain in TRUSTED_DOMAINS)

def get_today_stats():
    """
    Get or initialize today's statistics.
    
    Returns:
        dict: Today's statistics including URLs scanned and threats blocked
    """
    today = datetime.now().date().isoformat()
    if today not in stats["daily_stats"]:
        stats["daily_stats"][today] = {
            "urls_scanned": 0,
            "threats_blocked": 0
        }
    return stats["daily_stats"][today]

class URLInput(BaseModel):
    """
    Pydantic model for URL input validation.
    Ensures the input contains a valid URL string.
    """
    url: str

@app.post("/predict_url")
async def predict_url(input_data: URLInput):
    """
    Main endpoint for URL phishing prediction.
    Processes the URL and returns prediction results.
    
    Args:
        input_data (URLInput): The URL to analyze
        
    Returns:
        dict: Prediction results including safety status and features
        
    Raises:
        HTTPException: If there's an error in processing the URL
    """
    start_time = datetime.now()
    
    try:
        url = input_data.url
        domain = get_domain(url)

        # Check if domain is trusted before running ML prediction
        if is_trusted_domain(domain):
            result = {
                "url": url,
                "isPhishing": False,
                "timestamp": datetime.now().isoformat(),
                "message": "URL is from a trusted domain"
            }
        else:
            # Use ML model to predict if URL is phishing
            prediction_result = predictor.predict_from_url(url)
            
            if "error" in prediction_result:
                raise HTTPException(status_code=500, detail=prediction_result["error"])
                
            result = {
                "url": url,
                "isPhishing": prediction_result["prediction"] == 0,  # 0 is phishing, 1 is legitimate
                "timestamp": datetime.now().isoformat(),
                "message": f"URL is {prediction_result['result']}",
                "features": prediction_result.get("features", {})
            }

        # Update scan history
        scan_history.insert(0, result)
        
        # Keep only last 10 scans in history
        if len(scan_history) > 10:
            scan_history.pop()
            
        # Update daily statistics
        today_stats = get_today_stats()
        today_stats["urls_scanned"] += 1
        if result["isPhishing"]:
            today_stats["threats_blocked"] += 1
        
        # Track and update response time metrics
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        stats["response_times"].append(response_time)
        # Keep only last 100 response times for average calculation
        stats["response_times"] = stats["response_times"][-100:]
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_history():
    """
    Get the scan history.
    
    Returns:
        list: List of recent URL scan results
    """
    return scan_history

@app.delete("/history")
async def clear_history():
    """
    Clear the scan history.
    
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If there's an error clearing history
    """
    try:
        scan_history.clear()
        return {"message": "History cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/extension_stats")
async def get_extension_stats():
    """
    Get statistics for the browser extension.
    Includes daily scan counts and average response time.
    
    Returns:
        dict: Statistics including URLs scanned, threats blocked, and response time
    """
    today_stats = get_today_stats()
    avg_response_time = sum(stats["response_times"][-100:]) / len(stats["response_times"][-100:]) if stats["response_times"] else 0
    
    return {
        "urls_scanned_today": today_stats["urls_scanned"],
        "threats_blocked_today": today_stats["threats_blocked"],
        "avg_response_time": round(avg_response_time)
    }

@app.get("/")
async def root():
    """
    Root endpoint to check if API is running.
    
    Returns:
        dict: Simple status message
    """
    return {"message": "PhishShield API is running"}

@app.options("/{path:path}")
async def options_handler():
    """
    Handle CORS preflight requests.
    
    Returns:
        dict: OK message
    """
    return {"message": "OK"} 