from flask import Flask, request, render_template, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
from functools import wraps

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"

# TODO: Change the secret key to a secure value before deployment
app.secret_key = "supersecretkey"

# Simulated database for storing uploaded files information and user credentials
uploaded_files = []
users = {
    "operation_user": {"password": "operation_password", "role": "operation"},
    "client_user": {"password": "client_password", "role": "client"},
}


# Helper function to authenticate users
def authenticate(username, password):
    if username in users and users[username]['password'] == password:
        return True
    return False


# Decorator function to enforce authentication
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return render_template('login.html', message='Authentication failed'), 401
        username = session['username']
        if not authenticate(username, users[username]['password']):
            return render_template('login.html', message='Authentication failed'), 401
        return f(*args, **kwargs)

    return decorated


# Decorator function to enforce role-based authorization
def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return render_template('login.html', message='Authentication failed'), 401
            username = session['username']
            if not authenticate(username, users[username]['password']):
                return render_template('login.html', message='Authentication failed'), 401
            if users[username]['role'] != role:
                return render_template('index.html', message='Access denied'), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Index route
@app.route('/')
def index():
    return render_template('index.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            session['username'] = username
            return redirect(
                url_for('upload_file') if users[username]['role'] == 'operation' else url_for('client_files'))
        else:
            return render_template('login.html', message='Invalid credentials')
    return render_template('login.html')


# Route for Operation User to upload file
@app.route('/upload-file', methods=['GET', 'POST'])
@requires_auth
@requires_role('operation')
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            return render_template('upload.html', message='No file uploaded')

        # Check file type
        allowed_extensions = {'pptx', 'docx', 'xlsx'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return render_template('upload.html', message='File type not allowed')

        # Save file to uploads folder
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Store file info (for demonstration, use a proper database in production)
        uploaded_files.append({'filename': filename, 'uploader': session['username']})

        return redirect(url_for('upload_file'))

    return render_template('upload.html')


# Route for Client User to list uploaded files
@app.route('/client-files')
@requires_auth
@requires_role('client')
def client_files():
    return render_template('client_files.html', uploaded_files=uploaded_files)


# Route for Client User to download file
@app.route('/download-file/<filename>')
@requires_auth
@requires_role('client')
def download_file(filename):
    # Check if the file exists
    file_info = next((file for file in uploaded_files if file['filename'] == filename), None)
    if not file_info:
        return render_template('download.html', message='File not found')

    # Generate a secure URL for downloading the file
    download_url = url_for('download', filename=filename, _external=True)

    return render_template('download.html', download_link=download_url)


# Route to handle the actual file download
@app.route('/download/<filename>')
@requires_auth
@requires_role('client')
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return render_template('download.html', message='File not found')

    return send_file(file_path, as_attachment=True)


# Route for new clients to sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username is already taken
        if username in users:
            return render_template('signup.html', message='Username already exists')

        # Add new user to the database (simulated for demo)
        users[username] = {'password': password, 'role': 'client'}

        return redirect(url_for('login'))

    return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True)