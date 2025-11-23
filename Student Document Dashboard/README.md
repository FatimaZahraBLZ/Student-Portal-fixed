
  # Student Document Dashboard

  This is a code bundle for Student Document Dashboard. The original project is available at https://www.figma.com/design/UmdHXSFqj7G1pFPnIK4ZxM/Student-Document-Dashboard.

  ## Running the code

  Run `npm install` to install the dependencies.

  and also `npm install --save-dev @types/react @types/react-dom` to get rid of the error of the react type.

  Run `npm run dev` to start the development server.

  Before running the backend python first install the requirements `pip install -r requirements.txt` 

  Then run the backend `python app.py` or for me `C:\Python314\python.exe app.py`

  To run the app in the burp browser run the app with the commande `npm run dev -- --host 0.0.0.0`


#  FIXED VERSION — Security Improvements & IDOR Mitigation Summary

This section documents every security improvement applied in the **fixed version** of the Student Document Portal.
It explains how the updated backend and frontend eliminate the IDOR vulnerabilities present in the intentionally weak version.

The improvements include:

* Secure JWT authentication
* Server-controlled user identity
* UUID document identifiers
* Proper authorization checks
* Removal of unsafe request parameters
* Full backend-side access control enforcement

---

##  **PART 1 — Secure JWT Authentication (Replacing User-Controlled Identity)**

###  Previous Behavior (Vulnerable)

* The client sent `user_id` in requests (example: `GET /api/documents?user_id=2`).
* The server **trusted** this value.
* Attackers could replace `user_id` with another student’s ID → **IDOR**.

###  New Behavior (Fixed)

The server now generates a secure JWT token:

```python
payload = {
    "sub": user.id,
    "email": user.email,
    "iat": datetime.datetime.now(datetime.timezone.utc),
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=app.config["JWT_EXPIRATION_SECONDS"])
}
token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
```

###  Why this prevents IDOR

* The client can no longer control or fake the identity.
* `user_id` is taken from the **signed JWT**, not from user input.
* Only the server determines the authenticated user.

---

##  **PART 2 — Extracting Authenticated User Identity From JWT**

Our `auth_required` middleware now decodes the token:

```python
payload = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
user_id = payload.get("sub")
```

And sets:

```python
g.current_user = user
```

###  Why this prevents IDOR

Every request now has a **server-verified identity**, independent of any client parameters.
Nothing coming from the client is trusted.

---

##  **PART 3 — Switching to UUID Document IDs (Non-Predictable)**

Old version:

* Document IDs were integers (1, 2, 3...) → easy to guess.

New version:

```python
id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
```

###  Why this prevents IDOR

* UUIDs are extremely hard to guess, brute-force, or enumerate.
* Even if authorization failed, guessing another user’s UUID would be nearly impossible.
* Combined with access control, the system becomes highly secure.

---

##  **PART 4 — Secure Upload Logic (No More Impersonation)**

Old version:

* Upload endpoint accepted `user_id` from the client → attacker could upload files as someone else.

New version:

```python
doc = Document(
    user_id=g.current_user.id,
    original_name=file.filename,
    stored_name=stored_name
)
```

###  Why this prevents IDOR

* The server forces the document to belong to the **authenticated user only**.
* Impersonation is impossible.

---

##  **PART 5 — Fixed Document Listing (IDOR #1 Eliminated)**

Old behavior:

```python
docs = Document.query.filter_by(user_id=user_id)
```

New behavior:

```python
docs = Document.query.filter_by(user_id=g.current_user.id).all()
```

###  Why this prevents IDOR

* A user only receives documents where `user_id == current_user.id`
* Changing query parameters no longer reveals another student's files.

---

##  **PART 6 — Fixed Download Endpoint (IDOR #2 Eliminated)**

Old behavior:

* The server **did not check** whether the file belonged to the user.

New behavior:

```python
if doc.user_id != g.current_user.id:
    return jsonify({"error": "Not authorized to download this file"}), 403
```

###  Why this prevents IDOR

Even if an attacker tries:

```
/api/documents/download?file_id=<another-user-uuid>
```

The server responds with:

```
403 Forbidden — Not authorized
```

Unauthorized file access is completely prevented.

---

##  **PART 7 — Removing user_id From the Frontend (Critical Fix)**

Old version:

```ts
fetch(`${API_BASE_URL}/api/documents?user_id=${userId}`)
```

New version:

```ts
fetch(`${API_BASE_URL}/api/documents`, {
    headers: { Authorization: `Bearer ${token}` }
});
```

###  Why this prevents IDOR

* The frontend no longer sends any user identity.
* Identity is determined exclusively by the backend.
* Attackers cannot modify identity-related data using Burp Suite.


# **PART 8 — Logging & Rate Limiting (Final Fix for Layer D)**

###  **Previous Behavior (Vulnerable)**

In the weak version:

* Unauthorized access attempts were ignored
* Repeated malicious requests were not detected
* Attackers could brute-force file IDs or hammer endpoints
* No logs existed for forensic analysis or incident response

##  **New Behavior — Real Logging + Intelligent Rate Limiting**

Our backend now implements:

###  **1. Logging of Unauthorized Access Attempts**

Any suspicious behavior is logged in `security.log`, including:

* Unauthorized file downloads
* Invalid token usage
* Blocked IP addresses
* Excessive failed requests

Example log entry:

```
WARNING — Unauthorized download attempt: user=1 tried file=<uuid> from IP=127.0.0.1
```

This provides:

* Full traceability
* Intrusion detection
* Evidence for security analysis

---

###  **2. Rate Limiting & IP Blocking**

To prevent brute-force attacks, Our backend tracks failed attempts:

* Each bad request increments a counter
* After **10 failed attempts**, the IP is **blocked for 60 seconds**
* Further requests return:

```json
{ "error": "Too many failed attempts. Try again later." }
```

Blocked IPs are logged:

```
IP blocked due to excessive failures: 127.0.0.1
```

This stops:

* Token brute force
* File enumeration attempts
* Burp Suite automated scanning
* Repeated unauthorized downloads

---

##  **Why This Fix Matters**

This aligns with:

* OWASP API Security (API4:2019 — Rate Limiting)
* OWASP Logging & Monitoring recommendations
* CWE-307 (Excessive Authentication Attempts)
* CWE-778 (Insufficient Logging)

Our application can now:

* Detect attacks
* Slow down malicious users
* Prevent enumeration attacks
* Produce logs for auditing and project evaluation

---

##  **How It Completes Layer D Requirements**

| Requirement                      | Status                             |
| -------------------------------- | ---------------------------------- |
| Log unauthorized access          |  Implemented                       |
| Log suspicious download attempts |  Implemented                       |
| Track repeated failures          |  Implemented                       |
| Block abusive IPs                |  60-second block after 10 failures |
| Provide forensic visibility      |  Log stored in `security.log`      |



## **PART 9 — Strengthened Input Validation & Safe File Handling (Final Fix for Layer E)**

##  **New Behavior — Full PDF Validation with MIME + Header Checks**

Our backend now uses a **three-layer validation strategy**, ensuring that uploaded files are *real* PDFs.

###  **1. Browser MIME-Type Check**

```python
if file.mimetype != "application/pdf":
    return False
```

---

###  **2. File Magic Header Check**

The first bytes of every valid PDF must start with:

```
%PDF
```

Our backend now checks this signature:

```python
header = file.read(4)
file.seek(0)
if header != b"%PDF":
    return False
```

---

###  **3. File Extension Check (Defense in Depth)**

```python
if not file.filename.lower().endswith(".pdf"):
    return False
```

All **three** conditions must be met before the file is accepted.

---

##  **Why This Fix Matters**

This implementation ensures:

* Attackers cannot upload images disguised as PDFs
* Malware renamed to `.pdf` is rejected
* File parsing vulnerabilities are mitigated
* Backend behavior aligns with real PDF structure standards

This update follows best practices from:

* **OWASP Input Validation**
* **CWE-434 – Unrestricted File Upload**
* **CWE-552 – Insecure File Handling**

---

##  **How It Completes Layer E Requirements**

Our system now satisfies every requirement in **Layer E**:

| Requirement                  | Status                                          |
| ---------------------------- | ----------------------------------------------- |
| Validate file metadata       |  MIME + header validation                       |
| Prevent extension spoofing   |  Magic header prevents PNG/JPG disguised as PDF |
| Safe file handling           |  `secure_filename()` used                       |
| Store files outside web root |  Stored inside `uploads/` directory             |
| Safe download headers        |  Provided by `send_from_directory()`            |

---

##  **Final Summary — Layer E Fully Completed**

With this update, Our backend now enforces **strong, industry-grade PDF validation** and **secure file handling**. Combined with:

* JWT-based identity control
* Ownership checks on every file operation
* UUID document IDs
* Rate limiting
* Logging of suspicious actions
* Removal of user-controlled identity parameters

Our system now meets **all Fix-It requirements** and follows secure access-control and secure upload best practices.





  