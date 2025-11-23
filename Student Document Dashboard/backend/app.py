import os
import time
import datetime
import uuid
from functools import wraps
from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    g
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging
import jwt
from collections import defaultdict

# ============================================================
#   CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///student_portal.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-demo-key")
app.config["JWT_EXPIRATION_SECONDS"] = 3600
app.config["MAX_UPLOAD_SIZE_MB"] = 10

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
CORS(
    app,
    origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    supports_credentials=False,
)

# ============================================================
#   LOGGING CONFIG (SECURITY LOG)
# ============================================================

logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s",
)

# ============================================================
#   RATE LIMITING (BASIC)
# ============================================================

FAILED_ATTEMPTS = defaultdict(int)
BLOCK_THRESHOLD = 10
BLOCK_DURATION = 60  # 1 minute
BLOCKED_IPS = {}

def is_ip_blocked(ip):
    if ip in BLOCKED_IPS:
        if time.time() < BLOCKED_IPS[ip]:
            return True
        else:
            del BLOCKED_IPS[ip]
    return False

def register_failed_attempt(ip):
    FAILED_ATTEMPTS[ip] += 1
    if FAILED_ATTEMPTS[ip] >= BLOCK_THRESHOLD:
        BLOCKED_IPS[ip] = time.time() + BLOCK_DURATION
        logging.warning(f"IP blocked due to excessive failures: {ip}")

# ============================================================
#   DATABASE MODELS
# ============================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Document(db.Model):
    """ Unique UUID for each document, UUIDs are extremely hard to guess or enumerate.
     Even without authorization checks, this reduces risk drastically. """
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ============================================================
#   UTILS
# ============================================================

def serialize_document(doc):
    return {
        "id": doc.id,
        "original_name": doc.original_name,
        "stored_name": doc.stored_name,
        "uploaded_at": doc.uploaded_at.isoformat(),
    }

def validate_pdf(file):
    # 1) Check browser-reported MIME type
    if file.mimetype != "application/pdf":
        return False

    # 2) Check file signature (first bytes)
    header = file.read(4)
    file.seek(0)  # Reset pointer

    if header != b"%PDF":
        return False

    # 3) Check filename extension
    if not file.filename.lower().endswith(".pdf"):
        return False

    return True


def ensure_safe_filename(filename):
    safe = secure_filename(filename)
    return safe

# ============================================================
#   MOCK USER SEEDING
# ============================================================

def seed_mock_user():
    existing = {u.email for u in User.query.all()}
    mock_users = [
        ("test@student.com", "password123"),
        ("test1@student.com", "password123"),
    ]

    created_any = False
    for email, pwd in mock_users:
        if email not in existing:
            u = User(email=email, password_hash=generate_password_hash(pwd))
            db.session.add(u)
            created_any = True

    if created_any:
        db.session.commit()
        print("[+] Mock users created.")

# ============================================================
#   AUTHENTICATION
# ============================================================

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr

        if is_ip_blocked(ip):
            logging.warning(f"Blocked IP attempted request: {ip}")
            return jsonify({"error": "Too many failed attempts. Try again later."}), 429

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            register_failed_attempt(ip)
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(" ", 1)[1].strip()

        try:
            #auth_required decorator decodes the JWT token to verify the user's identity before allowing access to protected routes.
            payload = jwt.decode(
                token,
                app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            register_failed_attempt(ip)
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            register_failed_attempt(ip)
            return jsonify({"error": "Invalid token"}), 401

        user = User.query.get(payload.get("sub"))
        if not user:
            register_failed_attempt(ip)
            return jsonify({"error": "User not found"}), 401

        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper

# ============================================================
#   LOGIN
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = request.remote_addr
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        register_failed_attempt(ip)
        return jsonify({"error": "Invalid credentials"}), 401

    # Reset failures on successful login
    FAILED_ATTEMPTS[ip] = 0

    payload = {
        "sub": user.id,
        "email": user.email,
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(seconds=app.config["JWT_EXPIRATION_SECONDS"]),
    }

    #generate a secure JWT token at login This ensures the true user identity is embedded in the token, not supplied by the client.

    token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "email": user.email
        },
        "token": token
    })

# ============================================================
#   UPLOAD DOCUMENT
# ============================================================

@app.route("/api/documents/upload", methods=["POST"])
@auth_required
def upload_document():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if not validate_pdf(file):
        return jsonify({"error": "Only PDF files are allowed"}), 400

    safe_original = ensure_safe_filename(file.filename)
    timestamp = int(time.time())
    stored_name = f"{g.current_user.id}_{timestamp}_{safe_original}"

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    file.save(save_path)

    doc = Document(
        user_id=g.current_user.id,
        original_name=safe_original,
        stored_name=stored_name
    )
    db.session.add(doc)
    db.session.commit()

    return jsonify({
        "message": "File uploaded successfully",
        "document": serialize_document(doc)
    })

# ============================================================
#   LIST DOCUMENTS
# ============================================================

@app.route("/api/documents", methods=["GET"])
@auth_required
def list_documents():
    """ A user can only retrieve their own documents because the filter uses:
     - the authenticated user's ID
     - extracted from JWT
     - stored in g.current_user.id """
    docs = Document.query.filter_by(user_id=g.current_user.id).all()
    return jsonify([serialize_document(d) for d in docs])

# ============================================================
#   DOWNLOAD DOCUMENT
# ============================================================

@app.route("/api/documents/download", methods=["GET"])
@auth_required
def download_document():
    ip = request.remote_addr
    doc_id = request.args.get("file_id")

    if not doc_id:
        return jsonify({"error": "file_id is required"}), 400

    doc = Document.query.get(doc_id)

    if not doc:
        return jsonify({"error": "File not found"}), 404
    
    """Even if an attacker tries: /file_id=<another user's document uuid> 
        Does this file belong to the authenticated user? If not,
        they will be blocked here because the user_id won't match."""
    
    if doc.user_id != g.current_user.id:
        logging.warning(
            f"Unauthorized download attempt: "
            f"user={g.current_user.id} tried file={doc_id} from IP={ip}"
        )
        register_failed_attempt(ip)
        return jsonify({"error": "Not authorized to download this file"}), 403

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        doc.stored_name,
        as_attachment=True
    )

# ============================================================
#   APP STARTUP
# ============================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_mock_user()

    print("Secure Student Portal API running on http://127.0.0.1:5000")
    app.run(debug=True)
