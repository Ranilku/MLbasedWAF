import joblib
import urllib.parse
import numpy as np
from flask import Flask, request, jsonify, redirect
import requests
import re

# Load the trained XGBoost model
model = joblib.load(r'c:\waf\xgboost_model.joblib')

# Backend server details
backend_host = 'http://192.168.0.37'  # Backend server IP or domain
backend_port = 5000  # Backend server port

# Flask app for WAF
app = Flask(__name__)

# Define the XSS, LFI, Command Injection, and SQL Injection check functions
def xss_chk(url):
    decoded_url = urllib.parse.unquote(url)
    xss_patterns = re.compile(r'(<|>|%3C|%3E|script|alert|document\.|onload=|onerror=|eval\(|expression\(|prompt\(|confirm\()')
    return 1 if xss_patterns.search(decoded_url) else 0

def lfi_chk(url):
    decoded_url = urllib.parse.unquote(url)
    lfi_patterns = re.compile(r'(\.\./|\.\./|/etc/passwd|/proc/self/environ|/windows/win.ini)')
    return 1 if lfi_patterns.search(decoded_url) else 0

def command_injection_chk(url):
    decoded_url = urllib.parse.unquote(url)
    cmd_injection_patterns = re.compile(r'(&&|\|\||;|`|>|<|\$\(.*\)|\|)')
    return 1 if cmd_injection_patterns.search(decoded_url) else 0

def sql_injection_chk(url):
    decoded_url = urllib.parse.unquote(url)
    sql_injection_patterns = re.compile(r'(select.*from|union.*select|insert.*into|drop.*table|update.*set|delete.*from|--|\')')
    return 1 if sql_injection_patterns.search(decoded_url) else 0

# Feature extraction function (based on training features)
def extract_features(url):
    decoded_url = urllib.parse.unquote(url)  # Decode URL
    
    # Binary features for XSS, LFI, Command Injection, SQL Injection
    is_xss = xss_chk(decoded_url)
    is_lfi = lfi_chk(decoded_url)
    is_oci = command_injection_chk(decoded_url)
    is_sqli = sql_injection_chk(decoded_url)

    # Count-based features
    questionmark_count = decoded_url.count('?')
    equal_count = decoded_url.count('=')
    and_count = decoded_url.count('&')
    or_count = decoded_url.count('|')
    dot_count = decoded_url.count('.')
    at_count = decoded_url.count('@')
    underscore_count = decoded_url.count('_')
    semicolon_count = decoded_url.count(';')
    subdir_count = decoded_url.count('/')
    total_digits_in_url = sum(c.isdigit() for c in decoded_url)
    total_letters_in_url = sum(c.isalpha() for c in decoded_url)

    # Has extension feature
    has_extension = 1 if '.' in decoded_url.split('/')[-1] else 0

    # Return the feature array (make sure there are 16 features)
    return np.array([
        is_xss, is_lfi, is_oci, is_sqli, 
        questionmark_count, equal_count, and_count, or_count, 
        dot_count, at_count, underscore_count, semicolon_count, 
        subdir_count, total_digits_in_url, total_letters_in_url, 
        has_extension
    ]).reshape(1, -1)  # Reshape to (1, 16) to pass to model

# Route to intercept all incoming traffic and run the WAF checks
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def waf(path):
    # Full request URL (path + query string)
    full_url = request.url

    # Extract features and predict using the XGBoost model
    features = extract_features(full_url)
    prediction = model.predict(features)

    # Define the feature names
    feature_names = [
        'is_xss', 'is_lfi', 'is_oci', 'is_sqli', 
        'questionmark_count', 'equal_count', 'and_count', 'or_count', 
        'dot_count', 'at_count', 'underscore_count', 'semicolon_count', 
        'subdir_count', 'total_digits_in_url', 'total_letters_in_url', 
        'has_extension'
    ]

    # Create a dictionary pairing feature names with values and convert to regular Python types
    extracted_features = {name: int(value) if isinstance(value, np.integer) else float(value)
                          for name, value in zip(feature_names, features.flatten())}

    # Prepare the extracted features as an HTML table with smaller font
    features_table = "<table style='border: 1px solid #ddd; border-collapse: collapse; position: absolute; bottom: 20px; left: 20px;'>"
    features_table += "<tr><th style='border: 1px solid #ddd; padding: 8px; font-size: 12px;'>Feature</th><th style='border: 1px solid #ddd; padding: 8px; font-size: 12px;'>Value</th></tr>"
    for feature, value in extracted_features.items():
        features_table += f"<tr><td style='border: 1px solid #ddd; padding: 8px; font-size: 12px;'>{feature}</td><td style='border: 1px solid #ddd; padding: 8px; font-size: 12px;'>{value}</td></tr>"
    features_table += "</table>"

    if prediction == 1:
        # Generate a colorful HTML response for blocked traffic
        return f'''
        <html>
        <head>
            <title>Blocked by WebDefender</title>
            <style>
                body {{
                    background-color: #f8d7da;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                }}
                h1 {{
                    color: #721c24;
                    font-size: 48px;
                }}
                p {{
                    color: #721c24;
                    font-size: 18px;
                }}
                .message-box {{
                    border: 2px solid #f5c6cb;
                    background-color: #f8d7da;
                    padding: 20px;
                    border-radius: 10px;
                    display: inline-block;
                }}
                .contact {{
                    font-size: 16px;
                    color: #155724;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <h1>Access Blocked</h1>
            <div class="message-box">
                <p>WebDefender has blocked your request as we suspect the traffic is malicious.</p>
                <p>If you believe this is an error, please contact support at <b>admin@webdefender.com</b>.</p>
            </div>
            <div class="contact">
                <p>Reason: Potential attack detected based on traffic analysis.</p>
            </div>
            {features_table} <!-- Insert the feature table here -->
        </body>
        </html>
        ''', 403
    else:
        # If traffic is legitimate, forward it to the backend server
        backend_url = f"{backend_host}:{backend_port}/{path}"
        if request.method == 'POST':
            response = requests.post(backend_url, data=request.form)
        else:
            response = requests.get(backend_url)

        # Return the backend response
        return (response.content, response.status_code, response.headers.items())


# Run the WAF app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
