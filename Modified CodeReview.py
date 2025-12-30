# Secure version of ITS4050 CodeReview.py
from flask import Flask, request, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
# Use an environment variable for SECRET_KEY in real deployments
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-not-for-prod')

# Dummy "user store" with hashed passwords (in real apps use a proper DB)
USERS = {
    'admin': generate_password_hash('adminpassword'),
    'user': generate_password_hash('userpassword'),
}

LOGIN_FORM = """
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post" action="{{ url_for('login') }}">
  <label>Username: <input name="username" required></label><br>
  <label>Password: <input name="password" type="password" required></label><br>
  <button type="submit">Login</button>
</form>
{% if error %}
  <p style="color:red;">{{ error }}</p>
{% endif %}
"""

RESULT_TEMPLATE = """
<!doctype html>
<title>Result</title>
<h2>{{ message }}</h2>
<!-- Do NOT echo raw queries or sensitive input back to the client -->
"""

@app.route('/')
def home():
    return "Welcome. Go to /login to sign in."

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Use GET to show form, POST to submit credentials
    if request.method == 'GET':
        return render_template_string(LOGIN_FORM)

    # For POST: collect form data (Flask automatically decodes and Jinja will escape)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    # Input validation: basic checks
    if not username or not password:
        return render_template_string(LOGIN_FORM, error="Username and password required")

    # AUTH: use secure comparison to hashed password
    stored_hash = USERS.get(username)
    if stored_hash and check_password_hash(stored_hash, password):
        message = f"Successfully logged in as {username}!"
        # In production, set secure session cookies, avoid sensitive info in responses
        return render_template_string(RESULT_TEMPLATE, message=message)

    # Authentication failed: generic message (avoid revealing which field failed)
    return render_template_string(RESULT_TEMPLATE, message="Login failed!")

if __name__ == '__main__':
    # Do NOT enable debug=True in production. This uses the default (False) here.
    app.run()
