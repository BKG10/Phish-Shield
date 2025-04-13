# Phishing Detection Chrome Extension using Machine Learning
This project is a browser-based phishing detection system implemented as a Chrome Extension that leverages machine learning models to identify and block phishing websites in real-time. It is part of a research initiative focused on enhancing web security through intelligent URL and content-based analysis.

**🚀 Features**

  🔍 Real-time detection of phishing URLs while browsing

  🧠 Backend powered by an optimized XGBoost machine learning model with 98.5% accuracy

  📦 Lightweight frontend Chrome extension with clean UI

  📈 Extracts over 30 handcrafted features from the webpage and URL

  ⚡ FastAPI-based backend server for model inference

  🔗 REST API integration between extension and ML model

  🔐 Privacy-friendly (no user data is stored)

**📂 Project Structure**
  📁 frontend/ – Chrome extension frontend (HTML + JS)
  📁 backend/ – Python backend with FastAPI and XGBoost model

app.py: API endpoints

url_feature_extractor.py: Feature engineering logic

best_xgb_model.pkl: Trained ML model

📁 dataset/ – Phishing & legitimate URL dataset (for training)

📁 notebook/ – Model training & evaluation notebooks

**🛠️ Technologies Used**
  Machine Learning: XGBoost, Scikit-learn

  Web: JavaScript, HTML, Chrome APIs

  Backend: Python, FastAPI

  Tools: Pandas, NumPy, Joblib

**🧪 How It Works**
  The user visits a website.

  The extension captures the URL and webpage data.

  Extracted features are sent to the FastAPI backend.

  The trained ML model predicts whether the URL is phishing or safe.

  The result is displayed to the user in real-time.

**🎓 Project Context**
This extension is the implementation part of a research project on phishing detection using machine learning. The goal is to build a practical, scalable solution for securing users against phishing attacks during regular browsing.

📜 License
This project is open-source and available under the MIT License.

**If you want to use this just download it as a zip and then unzip it in your computer and enable the developer mode in chrome under the extension and load unpacked the Frontend Folder there pin it and you are ready to go**

