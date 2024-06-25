from flask import Flask, request, render_template, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from functools import wraps

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"

# Load environment variables
load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")
username = os.getenv("USER")
password = os.getenv("PWD")
host = os.getenv("HOST")
db_name = os.getenv("DB_NAME")
port = os.getenv("PORT")
# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+mysqlconnector://{username}:{password}@{host}:{port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Ensure the upload folder exists
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])


# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploader = db.Column(db.String(80), nullable=False)


# Helper function to authenticate users
def authenticate(username, password):
    user = User.query.filter_by(username=username, password=password).first()
    return user is not None


# Decorator function to enforce authentication
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return render_template("index.html", message="Authentication failed"), 401
        username = session["username"]
        user = User.query.filter_by(username=username).first()
        if not user or not authenticate(username, user.password):
            return render_template("index.html", message="Authentication failed"), 401
        return f(*args, **kwargs)

    return decorated


# Decorator function to enforce role-based authorization
def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "username" not in session:
                return (
                    render_template("index.html", message="Authentication failed"),
                    401,
                )
            username = session["username"]
            user = User.query.filter_by(username=username).first()
            if (
                not user
                or not authenticate(username, user.password)
                or user.role != role
            ):
                return render_template("index.html", message="Access denied"), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Index route
@app.route("/")
def index():
    return render_template("index.html")


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if authenticate(username, password):
            session["username"] = username
            user = User.query.filter_by(username=username).first()
            return redirect(
                url_for("upload_file")
                if user.role == "operation"
                else url_for("client_files")
            )
        else:
            return render_template("index.html", error="Invalid credentials")
    return render_template("index.html")


# Route for Operation User to upload file
@app.route("/upload-file", methods=["GET", "POST"])
@requires_auth
@requires_role("operation")
def upload_file():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            return render_template("upload.html", message="No file uploaded")

        # Check file type
        allowed_extensions = {"pptx", "docx", "xlsx"}
        if (
            "." not in file.filename
            or file.filename.rsplit(".", 1)[1].lower() not in allowed_extensions
        ):
            return render_template(
                "upload.html", message="Only .pptx, .docx, .xlsx are allowed"
            )

        # Save file to uploads folder
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # Store file info in database
        uploaded_file = UploadedFile(filename=filename, uploader=session["username"])
        db.session.add(uploaded_file)
        db.session.commit()

        return render_template("upload.html", message="File uploaded")

    return render_template("upload.html")


# Route for Client User to list uploaded files
@app.route("/client-files")
@requires_auth
@requires_role("client")
def client_files():
    files = UploadedFile.query.all()
    return render_template("client_files.html", uploaded_files=files)


# Route for Client User to download file
@app.route("/download-file/<filename>")
@requires_auth
@requires_role("client")
def download_file(filename):
    # Check if the file exists in the database
    file_info = UploadedFile.query.filter_by(filename=filename).first()
    if not file_info:
        return render_template("download.html", message="File not found")

    # Generate a secure URL for downloading the file
    download_url = url_for("download", filename=filename, _external=True)

    return render_template("download.html", download_link=download_url)


# Route to handle the actual file download
@app.route("/download/<filename>")
@requires_auth
@requires_role("client")
def download(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(file_path):
        return render_template("download.html", message="File not found")

    return send_file(file_path, as_attachment=True)


# Route for new clients to sign up
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if username is already taken
        if User.query.filter_by(username=username).first():
            return render_template("signup.html", message="Username already exists")

        # Add new user to the database
        new_user = User(username=username, password=password, role="client")
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("signup.html")


if __name__ == "__main__":
    # Create tables
    with app.app_context():
        db.create_all()
        # Create a new user
        # new_user = User(username="admin", password="admin", role="operation")
        # db.session.add(new_user)
        # db.session.commit()
    app.run(debug=True)
