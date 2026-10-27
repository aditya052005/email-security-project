AI-Powered Email Security & Threat Analysis System

Project Overview

This project is a web-based application designed to analyze email content and identify potential phishing threats. It provides a risk score, prediction results, and detected URLs to help users understand suspicious emails.

Features

- Email content analysis
- Phishing and legitimate email prediction
- Risk score and risk-level display
- Suspicious URL pattern detection
- Analysis history dashboard
- Simple and user-friendly web interface

Technologies Used

- Python
- Flask
- Scikit-learn
- HTML and CSS
- Machine Learning (TF-IDF and Logistic Regression)

Installation

1. Install Python 3.

2. Install the required packages:
   
   "python3 -m pip install -r requirements.txt"

3. Run the application:
   
   "python3 app.py"

4. Open the browser and visit:
   
   "http://127.0.0.1:5000"

Project Structure

- "app.py" — Main Flask application
- "model.py" — Email classification model
- "templates/index.html" — Dashboard interface
- "screenshots/" — Project screenshots
- "requirements.txt" — Required Python packages

Limitations

The machine-learning model uses a small sample dataset for demonstration. Predictions may not always be accurate. URL detection is pattern-based and does not perform a live reputation check.

Student Details

Name: Aditya Raj
Roll Number: 2401720100010
Department: Computer Science & Engineering
Section: 3-D
Session: 2026–27

Disclaimer

This project is developed for academic and educational purposes. It should not be used as the sole method for deciding whether an email is safe.