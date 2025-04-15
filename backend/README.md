# PhishShield Backend

This is the backend service for the PhishShield phishing detection system.

## Deployment Instructions

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Local Development Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the development server:
```bash
uvicorn app:app --reload
```

### Deployment to Production

1. Make sure all dependencies are listed in `requirements.txt`

2. The application can be deployed to any platform that supports Python applications (Heroku, Railway, etc.)

3. For Heroku deployment:
```bash
heroku create your-app-name
git push heroku main
```

4. For Railway deployment:
- Connect your GitHub repository
- Select the backend directory
- Railway will automatically detect the Python application and deploy it

### Environment Variables

The following environment variables can be configured:
- `PORT`: The port number the server should listen on (default: 8000)
- `CORS_ORIGINS`: Comma-separated list of allowed origins for CORS (default: "*")

### API Documentation

Once deployed, the API documentation will be available at:
- Swagger UI: `/docs`
- ReDoc: `/redoc` 