from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import MySQLdb.cursors
import json
import time

# Initialize Flask App
app = Flask(__name__)
app.config["SECRET_KEY"] = "root"

# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "root"
app.config["MYSQL_DB"] = "blood_bank_db"

# Initialize MySQL
mysql = MySQL(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ========================== USER MODEL FOR FLASK-LOGIN ==========================
class User(UserMixin):
    def __init__(self, id, username, email, password, role):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.role = role

# Load User for Login Manager
@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    
    if user:
        return User(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            password=user['password'],
            role=user['role']
        )
    return None

# ========================== DATABASE INITIALIZATION ==========================
def init_db():
    cursor = mysql.connection.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(150) UNIQUE NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password VARCHAR(1000) NOT NULL,
            role VARCHAR(50) NOT NULL
        )
    ''')
    
    # Create blood_stock table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blood_stock (
            id INT AUTO_INCREMENT PRIMARY KEY,
            blood_type VARCHAR(10) NOT NULL,
            quantity INT NOT NULL
        )
    ''')
    
    # Create blood_requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blood_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hospital_name VARCHAR(100) NOT NULL,
            blood_type VARCHAR(5) NOT NULL,
            quantity VARCHAR(20) NOT NULL,
            status VARCHAR(20) DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create appointments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appointments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            donor_id INT NOT NULL,
            hospital_id INT NOT NULL,
            date DATE NOT NULL,
            status VARCHAR(20) DEFAULT 'Scheduled',
            FOREIGN KEY (donor_id) REFERENCES users(id),
            FOREIGN KEY (hospital_id) REFERENCES users(id)
        )
    ''')
    
    # Create notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            message VARCHAR(500) NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create donor_profiles table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS donor_profiles (
            id INT AUTO_INCREMENT PRIMARY KEY, 
            user_id INT NOT NULL, 
            blood_type VARCHAR(5) NOT NULL, 
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create hospital_profiles table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hospital_profiles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            hospital_name VARCHAR(100) NOT NULL,
            address VARCHAR(200),
            password varchar(100),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    mysql.connection.commit()
    cursor.close()

# ========================== FRONTEND ROUTES ==========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/bloodbank_dashboard")
@login_required
def bloodbank_dashboard():
    return render_template("bloodbank-dashboard.html")

@app.route("/login", methods=["GET"])
def bloodbank_login():
    return render_template("bloodbank-login.html")

@app.route("/book-appointment")
@login_required
def book_appointment():
    return render_template("book-appointment.html")

@app.route("/donation-history")
@login_required
def donation_history():
    return render_template("donation-history.html")

@app.route("/donor-dashboard")
@login_required
def donor_dashboard():
    return render_template("donor-dashboard.html")

@app.route("/donor-profile")
@login_required
def donor_profile():
    return render_template("donor-profile.html")

@app.route("/register/donor", methods=["GET", "POST"])
def donor_register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        blood_type = request.form.get("bloodType")
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            cursor.close()
            return render_template("donor-register.html", error="Username already exists")
        
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_email = cursor.fetchone()
        
        if existing_email:
            cursor.close()
            return render_template("donor-register.html", error="Email already exists")
        
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                      (username, email, hashed_password, "donor"))
        mysql.connection.commit()
        
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        
        cursor.execute('INSERT INTO donor_profiles (user_id, blood_type) VALUES (%s, %s)', 
                      (user['id'], blood_type))
        mysql.connection.commit()
        cursor.close()
        
        user_obj = User(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            password=user['password'],
            role=user['role']
        )
        
        login_user(user_obj)
        session["role"] = user['role']
        
        return redirect(url_for("donor_dashboard"))
    
    return render_template("donor-register.html")

@app.route("/register/hospital", methods=["GET", "POST"])
def hospital_register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hospital_name = request.form.get("hospitalName")
        address = request.form.get("address")
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            cursor.close()
            return render_template("hospital-register.html", error="Username already exists")
        
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_email = cursor.fetchone()
        
        if existing_email:
            cursor.close()
            return render_template("hospital-register.html", error="Email already exists")
        
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                      (username, email, hashed_password, "hospital"))
        mysql.connection.commit()
        
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        
        cursor.execute('INSERT INTO hospital_profiles (user_id, hospital_name, address) VALUES (%s, %s, %s)', 
                      (user['id'], hospital_name, address))
        mysql.connection.commit()
        cursor.close()
        
        user_obj = User(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            password=user['password'],
            role=user['role']
        )
        
        login_user(user_obj)
        session["role"] = user['role']
        
        return redirect(url_for("hospital_dashboard"))
    
    return render_template("hospital-register.html")

@app.route("/donor", methods=["GET", "POST"])
def donor_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND role = %s', (username, "donor"))
        user = cursor.fetchone()
        cursor.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                password=user['password'],
                role=user['role']
            )
            login_user(user_obj)
            session["role"] = user['role']
            return redirect(url_for("donor_dashboard"))
        else:
            return render_template("donor.html", error="Invalid username or password")
    
    return render_template("donor.html")

@app.route("/api/donor/profile", methods=["GET"])
@login_required
def get_donor_profile():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Fetch donor profile details
        cursor.execute('''
            SELECT u.username, u.email, dp.blood_type, 
                   (CASE WHEN COUNT(a.id) > 0 THEN 
                       MAX(a.date) 
                   ELSE 
                       NULL 
                   END) as last_donation,
                   (CASE WHEN NOW() > DATE_ADD(MAX(a.date), INTERVAL 3 MONTH) OR MAX(a.date) IS NULL THEN 
                       'Eligible' 
                   ELSE 
                       'Not Eligible' 
                   END) as eligibility_status
            FROM users u
            LEFT JOIN donor_profiles dp ON u.id = dp.user_id
            LEFT JOIN appointments a ON u.id = a.donor_id AND a.status = 'Completed'
            WHERE u.id = %s
            GROUP BY u.id, u.username, u.email, dp.blood_type
        ''', (current_user.id,))
        
        donor_profile = cursor.fetchone()
        cursor.close()
        
        if donor_profile:
            return jsonify({
                "username": donor_profile['username'],
                "email": donor_profile['email'],
                "blood_type": donor_profile['blood_type'] or 'Not specified',
                "last_donation": donor_profile['last_donation'],
                "is_eligible": donor_profile['eligibility_status'] == 'Eligible'
            })
        else:
            return jsonify({"error": "Donor profile not found"}), 404
    
    except Exception as e:
        print(f"Error fetching donor profile: {e}")
        return jsonify({"error": "Unable to fetch donor profile"}), 500

@app.route("/hospital", methods=["GET", "POST"])
def hospital_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND role = %s', (username, "hospital"))
        user = cursor.fetchone()
        cursor.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                password=user['password'],
                role=user['role']
            )
            login_user(user_obj)
            session["role"] = user['role']
            return redirect(url_for("hospital_dashboard"))
        else:
            return render_template("hospital.html", error="Invalid username or password")
    
    return render_template("hospital.html")

@app.route("/edit-profile")
@login_required
def edit_profile():
    return render_template("edit-profile.html")

@app.route("/api/hospital-profile", methods=["GET"])
@login_required
def get_hospital_profile():
    if current_user.role != "hospital":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Fetch hospital profile details
        cursor.execute('''
            SELECT u.username, u.email, hp.hospital_name, hp.address
            FROM users u
            JOIN hospital_profiles hp ON u.id = hp.user_id
            WHERE u.id = %s
        ''', (current_user.id,))
        
        hospital_profile = cursor.fetchone()
        cursor.close()
        
        if hospital_profile:
            return jsonify({
                "success": True,
                "hospitalName": hospital_profile['hospital_name'],
                "email": hospital_profile['email'],
                "address": hospital_profile['address']
            })
        else:
            return jsonify({"success": False, "message": "Hospital profile not found"}), 404
    
    except Exception as e:
        print(f"Error fetching hospital profile: {e}")
        return jsonify({"success": False, "message": "Unable to fetch hospital profile"}), 500

@app.route("/api/hospital-profile", methods=["POST"])
@login_required
def update_hospital_profile():
    if current_user.role != "hospital":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        data = request.json
        cursor = mysql.connection.cursor()
        
        # Update email in users table
        if "email" in data:
            cursor.execute('UPDATE users SET email = %s WHERE id = %s', 
                          (data["email"], current_user.id))
        
        # Update hospital details in hospital_profiles table
        if "hospitalName" in data or "address" in data:
            hospital_name = data.get("hospitalName")
            address = data.get("address")
            
            # Fetch current values first
            if hospital_name is None or address is None:
                cursor.execute('SELECT hospital_name, address FROM hospital_profiles WHERE user_id = %s',
                              (current_user.id,))
                current_data = cursor.fetchone()
                
                if current_data:
                    if hospital_name is None:
                        hospital_name = current_data[0]
                    if address is None:
                        address = current_data[1]
            
            cursor.execute('''
                UPDATE hospital_profiles 
                SET hospital_name = %s, address = %s 
                WHERE user_id = %s
            ''', (hospital_name, address, current_user.id))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True, "message": "Hospital profile updated successfully"})
    
    except Exception as e:
        print(f"Error updating hospital profile: {e}")
        return jsonify({"success": False, "message": "Unable to update hospital profile"}), 500

@app.route("/Hblood-requests")
@login_required
def hospital_blood_requests():
    print("Hospital blood requests route accessed")
    return render_template("Hblood-requests.html")

@app.route("/Hblood-pending")
@login_required
def hospital_blood_pending():
    print("Hospital blood pending route accessed")
    return render_template("pending-request.html")

@app.route("/Hblood-stock")
@login_required
def hospital_blood_stock():
    return render_template("Hblood-stock.html")

@app.route("/health-tips")
def health_tips():
    return render_template("health-tips.html")

@app.route("/hospital-dashboard")
@login_required
def hospital_dashboard():
    return render_template("hospital-dashboard.html")

@app.route("/manage-donors")
@login_required
def manage_donors():
    return render_template("manage-donors.html")

@app.route("/manage-hospitals")
@login_required
def manage_hospitals():
    return render_template("manage-hospitals.html")

@app.route("/request-history")
@login_required
def request_history():
    return render_template("request-history.html")

@app.route("/donor-notifications")
@login_required
def donor_notifications():
    if current_user.role != "donor":
        return redirect(url_for("donor_dashboard"))
    return render_template("donor-notifications.html")

@app.route("/hospital-notifications")
@login_required
def hospital_notifications():
    if current_user.role != "hospital":
        return redirect(url_for("hospital_dashboard"))
    return render_template("hospital-notifications.html")

@app.route("/admin-notifications")
@login_required
def admin_notifications():
    if current_user.role != "admin":
        return redirect(url_for("bloodbank_dashboard"))
    return render_template("admin-notifications.html")

@app.route("/approved-requests")
@login_required
def approved_requests():
    return render_template("approved-requests.html")

@app.route("/api/donor/donation-history", methods=["GET"])
@login_required
def get_donation_history():
    if current_user.role != "donor":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Get all completed appointments for the current donor
        cursor.execute('''
            SELECT a.date, hp.hospital_name as location, a.status
            FROM appointments a
            JOIN hospital_profiles hp ON a.hospital_id = hp.user_id
            WHERE a.donor_id = %s
            ORDER BY a.date DESC
        ''', (current_user.id,))
        
        appointments = cursor.fetchall()
        cursor.close()
        
        # Format dates for the frontend
        for appointment in appointments:
            appointment['date'] = appointment['date'].strftime("%Y-%m-%d")
            # Add standard blood donation volume
            appointment['bloodDonated'] = "450 ml" if appointment['status'] == 'Completed' else "N/A"
        
        return jsonify(appointments)
    
    except Exception as e:
        print(f"Error fetching donation history: {e}")
        return jsonify({"error": "Unable to fetch donation history"}), 500
@app.route("/bloodbank-request-history")
@login_required
def bloodbank_request_history():
    if current_user.role != "admin":
        return redirect(url_for("bloodbank_dashboard"))
    return render_template("request-history-bloodbank.html")

# ========================== API ROUTES ==========================
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (data["username"],))
    user = cursor.fetchone()
    cursor.close()

    if user and check_password_hash(user["password"], data["password"]):
        user_obj = User(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            password=user['password'],
            role=user['role']
        )
        login_user(user_obj)
        session["role"] = user['role']
        return jsonify({"success": True, "message": "Login successful!", "role": user['role']})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401
    
@app.route("/admin/send-notification", methods=["POST"])
@login_required
def send_notification():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.json
    role = data.get("role", "").strip()
    message = data.get("message", "").strip()

    if not role or role not in ["donor", "hospital"]:
        return jsonify({"success": False, "message": "Invalid recipient role"}), 400

    if not message:
        return jsonify({"success": False, "message": "Message cannot be empty"}), 400

    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Fetch users based on the selected role
        cursor.execute("SELECT id FROM users WHERE role = %s", (role,))
        users = cursor.fetchall()
        print(f"Users found for role {role}: {users}")  # Debug logging

        if not users:
            cursor.close()
            return jsonify({"success": False, "message": f"No {role}s found to notify"}), 404

        # Insert a notification for each user
        for user in users:
            user_id = user["id"]
            cursor.execute(
                "INSERT INTO notifications (user_id, message) VALUES (%s, %s)",
                (user_id, message)
            )

        mysql.connection.commit()
        cursor.close()

        return jsonify({"success": True, "message": f"Notification sent to all {role}s successfully!"})

    except Exception as e:
        print(f"Error sending notifications: {e}")
        return jsonify({"success": False, "message": "Failed to send notifications"}), 500
@app.route("/stream")
@login_required
def stream():
    def event_stream():
        last_id = 0
        while True:
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    "SELECT * FROM notifications WHERE id > %s AND user_id = %s AND is_read = 0 ORDER BY date",
                    (last_id, current_user.id)
                )
                notifications = cursor.fetchall()
                print(f"Notifications fetched for user {current_user.id}: {notifications}")  # Debug logging
                
                if notifications:
                    for notification in notifications:
                        last_id = notification["id"]
                        data = json.dumps({
                            "id": notification["id"],
                            "message": notification["message"],
                            "timestamp": notification["date"].strftime('%Y-%m-%d %H:%M:%S')
                        })
                        yield f"data: {data}\n\n"

                cursor.close()
            except Exception as e:
                print(f"Error in stream: {e}")
                time.sleep(2)  # Wait before retrying
                continue

            time.sleep(2)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute('SELECT * FROM users WHERE username = %s', (data["username"],))
    existing_user = cursor.fetchone()
    
    if existing_user:
        cursor.close()
        return jsonify({"success": False, "message": "Username already exists"}), 400
    
    cursor.execute('SELECT * FROM users WHERE email = %s', (data["email"],))
    existing_email = cursor.fetchone()
    
    if existing_email:
        cursor.close()
        return jsonify({"success": False, "message": "Email already exists"}), 400
    
    hashed_password = generate_password_hash(data["password"])
    cursor.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                  (data["username"], data["email"], hashed_password, data["role"]))
    mysql.connection.commit()
    
    cursor.execute('SELECT * FROM users WHERE username = %s', (data["username"],))
    user = cursor.fetchone()
    
    if data["role"] == "donor" and "blood_type" in data:
        cursor.execute('INSERT INTO donor_profiles (user_id, blood_type) VALUES (%s, %s)', 
                      (user['id'], data["blood_type"]))
    
    elif data["role"] == "hospital" and "hospitalName" in data:
        address = data.get("address", "")
        cursor.execute('INSERT INTO hospital_profiles (user_id, hospital_name, address) VALUES (%s, %s, %s)', 
                      (user['id'], data["hospitalName"], address))
    
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Registration successful!"}), 201

@app.route("/my-appointments")
@login_required
def my_appointments():
    if current_user.role != "donor":
        return redirect(url_for("donor_dashboard"))
    return render_template("my-appointments.html")

@app.route("/api/donor/appointments", methods=["GET"])
@login_required
def get_donor_appointments():
    print(f"Getting appointments for donor ID: {current_user.id}")
    if current_user.role != "donor":
        print("User is not a donor")
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    query = '''
        SELECT a.id, hp.hospital_name, a.date, a.status
        FROM appointments a
        JOIN hospital_profiles hp ON a.hospital_id = hp.user_id
        WHERE a.donor_id = %s
        ORDER BY a.date DESC
    '''
    print(f"Executing query: {query} with params ({current_user.id},)")
    cursor.execute(query, (current_user.id,))
    
    appointments = cursor.fetchall()
    print(f"Found {len(appointments)} appointments")
    cursor.close()
    
    for a in appointments:
        a["date"] = a["date"].strftime("%Y-%m-%d")

    return jsonify(appointments)

@app.route("/api/available-hospitals", methods=["GET"])
def get_available_hospitals():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        cursor.execute('''
            SELECT u.id, hp.hospital_name
            FROM users u
            JOIN hospital_profiles hp ON u.id = hp.user_id
            WHERE u.role = 'hospital'
            ORDER BY hp.hospital_name
        ''')
        
        hospitals = cursor.fetchall()
        cursor.close()
        
        return jsonify(hospitals)
    
    except Exception as e:
        print(f"Error fetching hospitals: {e}")
        return jsonify([]), 500

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()  # Clear the entire session to be thorough
    return jsonify({"success": True, "message": "Logged out successfully"})

@app.route("/api/users/profile", methods=["GET"])
@login_required
def get_profile():
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    })

@app.route("/api/users/profile", methods=["PUT"])
@login_required
def update_profile():
    data = request.json
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if "email" in data:
        cursor.execute('SELECT * FROM users WHERE email = %s AND id != %s', (data["email"], current_user.id))
        existing_email = cursor.fetchone()
        
        if existing_email:
            cursor.close()
            return jsonify({"success": False, "message": "Email already exists"}), 400
        
        cursor.execute('UPDATE users SET email = %s WHERE id = %s', (data["email"], current_user.id))
    
    if "password" in data:
        hashed_password = generate_password_hash(data["password"])
        cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, current_user.id))
    
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Profile updated successfully"})
@app.route("/api/blood-requests", methods=["GET"])
@login_required
def get_requests():
    if current_user.role not in ["admin", "hospital"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        if current_user.role == "admin":
            # Admins can see all requests
            cursor.execute('SELECT * FROM blood_requests')
        else:
            # Hospitals can only see their own requests
            cursor.execute(
                'SELECT hospital_name FROM hospital_profiles WHERE user_id = %s',
                (current_user.id,)
            )
            hospital = cursor.fetchone()
            
            if not hospital:
                cursor.close()
                return jsonify({"success": False, "message": "Hospital profile not found"}), 404

            hospital_name = hospital["hospital_name"]
            print(f"Fetching requests for hospital: {hospital_name}")  # Debug logging

            cursor.execute(
                'SELECT * FROM blood_requests WHERE hospital_name = %s',
                (hospital_name,)
            )

        requests = cursor.fetchall()
        print(f"Found {len(requests)} requests: {requests}")  # Debug logging
        cursor.close()
        
        for r in requests:
            r["created_at"] = r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify(requests)

    except Exception as e:
        print(f"Error fetching blood requests: {e}")
        return jsonify({"success": False, "message": "Failed to fetch blood requests"}), 500

@app.route("/api/blood-requests", methods=["POST"])
@login_required
def create_blood_request():
    if current_user.role != "hospital":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    data = request.json
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        'INSERT INTO blood_requests (hospital_name, blood_type, quantity) VALUES (%s, %s, %s)',
        (data["hospital_name"], data["blood_type"], data["quantity"])
    )
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Blood request created successfully"}), 201

@app.route("/api/admin/stats", methods=["GET"])
@login_required
def get_admin_stats():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Get total users count
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']
        
        # Get donor count
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE role = "donor"')
        donor_count = cursor.fetchone()['count']
        
        # Get hospital count
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE role = "hospital"')
        hospital_count = cursor.fetchone()['count']
        
        # Get total blood units
        cursor.execute('SELECT SUM(quantity) as total FROM blood_stock')
        result = cursor.fetchone()
        total_blood_units = result['total'] if result['total'] is not None else 0
        
        cursor.close()
        
        return jsonify({
            "success": True,
            "totalUsers": total_users,
            "donorCount": donor_count,
            "hospitalCount": hospital_count,
            "totalBloodUnits": total_blood_units
        })
        
    except Exception as e:
        print(f"Error fetching admin stats: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to fetch statistics"
        }), 500

@app.route("/api/blood-requests/<int:request_id>", methods=["PATCH"])
@login_required
def update_request(request_id):
    if current_user.role not in ["admin", "hospital"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.json
    
    # Check if the request exists
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE id = %s', (request_id,))
    request_data = cursor.fetchone()
    
    if not request_data:
        cursor.close()
        return jsonify({"success": False, "message": "Request not found"}), 404

    # Handle "Approved" status
    if "status" in data and data["status"] == "Approved":
        cursor.execute('UPDATE blood_requests SET status = %s WHERE id = %s', ("Approved", request_id))
        mysql.connection.commit()
        
        hospital_name = request_data["hospital_name"]
        blood_type = request_data["blood_type"]
        
        # Fetch hospital user_id
        cursor.execute('SELECT user_id FROM hospital_profiles WHERE hospital_name = %s', (hospital_name,))
        hospital_data = cursor.fetchone()
        
        if hospital_data:
            hospital_user_id = hospital_data["user_id"]
            notification_message_hospital = f"Your blood request (ID: {request_id}) has been approved."
            cursor.execute('INSERT INTO notifications (user_id, message) VALUES (%s, %s)', (hospital_user_id, notification_message_hospital))
        
        # Fetch all donors who match the blood type
        cursor.execute('''
            SELECT u.id 
            FROM users u 
            JOIN donor_profiles d ON u.id = d.user_id 
            WHERE d.blood_type = %s AND u.role = 'donor'
        ''', (blood_type,))
        
        donors = cursor.fetchall()
        print(f"Donors with blood type {blood_type}: {donors}")  # Debug logging
        
        if donors:
            for donor in donors:
                donor_user_id = donor["id"]
                notification_message_donor = f"A hospital ({hospital_name}) needs your blood type. Consider donating!"
                cursor.execute('INSERT INTO notifications (user_id, message) VALUES (%s, %s)', (donor_user_id, notification_message_donor))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True, "message": f"Request {request_id} approved and notifications sent."})

    # Handle "Cancelled" status
    elif "status" in data and data["status"] == "Cancelled":
        # Ensure only admins can cancel requests (optional, depending on your requirements)
        if current_user.role != "admin":
            cursor.close()
            return jsonify({"success": False, "message": "Only admins can cancel requests"}), 403

        # Update the request status to "Cancelled"
        cursor.execute('UPDATE blood_requests SET status = %s WHERE id = %s', ("Cancelled", request_id))
        mysql.connection.commit()
        
        # Fetch hospital details to send a notification
        hospital_name = request_data["hospital_name"]
        cursor.execute('SELECT user_id FROM hospital_profiles WHERE hospital_name = %s', (hospital_name,))
        hospital_data = cursor.fetchone()
        
        if hospital_data:
            hospital_user_id = hospital_data["user_id"]
            notification_message_hospital = f"Your blood request (ID: {request_id}) has been cancelled by the admin."
            cursor.execute('INSERT INTO notifications (user_id, message) VALUES (%s, %s)', (hospital_user_id, notification_message_hospital))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True, "message": f"Request {request_id} has been cancelled."})

    # If the status is neither "Approved" nor "Cancelled"
    cursor.close()
    return jsonify({"success": False, "message": "Invalid request status"}), 400

@app.route("/api/blood-stock", methods=["GET"])
@login_required
def get_blood_stock():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_stock')
    stock = cursor.fetchall()
    cursor.close()
    
    stock_dict = {s["blood_type"]: s["quantity"] for s in stock}
    return jsonify(stock_dict)

@app.route("/api/blood-stock", methods=["POST"])
@login_required
def update_blood_stock():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    data = request.json
    cursor = mysql.connection.cursor()
    
    for blood_type, quantity in data.items():
        cursor.execute('SELECT * FROM blood_stock WHERE blood_type = %s', (blood_type,))
        if cursor.fetchone():
            cursor.execute('UPDATE blood_stock SET quantity = %s WHERE blood_type = %s', (quantity, blood_type))
        else:
            cursor.execute('INSERT INTO blood_stock (blood_type, quantity) VALUES (%s, %s)', (blood_type, quantity))
    
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Blood stock updated successfully"})

@app.route("/blood-stock")
@login_required
def blood_stock_page():
    if current_user.role != "admin":
        return redirect(url_for("bloodbank_dashboard"))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_stock')
    stock = cursor.fetchall()
    cursor.close()
    return render_template("blood-stock.html", stock=stock)
@app.route("/api/book-appointment", methods=["POST"])
@login_required
def book_appointment_api():
    if current_user.role != "donor":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.json
    appointment_date = datetime.strptime(data["date"], "%Y-%m-%d").date()
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        'INSERT INTO appointments (donor_id, hospital_id, date) VALUES (%s, %s, %s)',
        (current_user.id, data["hospital_id"], appointment_date)
    )
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Appointment booked successfully!"})

@app.route("/api/appointments", methods=["GET"])
@login_required
def get_appointments():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if current_user.role == "donor":
        cursor.execute('SELECT * FROM appointments WHERE donor_id = %s', (current_user.id,))
    elif current_user.role == "hospital":
        cursor.execute('SELECT * FROM appointments WHERE hospital_id = %s', (current_user.id,))
    else:
        cursor.execute('SELECT * FROM appointments')
    
    appointments = cursor.fetchall()
    cursor.close()
    
    for a in appointments:
        a["date"] = a["date"].strftime("%Y-%m-%d")
    
    return jsonify(appointments)

@app.route("/api/notifications", methods=["GET"])
@login_required
def get_notifications():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM notifications WHERE user_id = %s ORDER BY date DESC', (current_user.id,))
        notifications = cursor.fetchall()
        print(f"Fetched notifications for user {current_user.id}: {notifications}")  # Debug logging
        cursor.close()
        
        for n in notifications:
            n["date"] = n["date"].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify(notifications)
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return jsonify({"error": "Unable to fetch notifications"}), 500

@app.route("/api/notifications/<int:notification_id>", methods=["PATCH"])
@login_required
def mark_notification_read(notification_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute(
        'SELECT * FROM notifications WHERE id = %s AND user_id = %s',
        (notification_id, current_user.id)
    )
    notification = cursor.fetchone()
    
    if not notification:
        cursor.close()
        return jsonify({"success": False, "message": "Unauthorized or notification not found"}), 403
    
    cursor.execute('UPDATE notifications SET is_read = TRUE WHERE id = %s', (notification_id,))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"success": True, "message": "Notification marked as read"})

@app.route("/api/donors")
@login_required
def get_donors():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Fetch all donors with their profiles
        cursor.execute('''
            SELECT u.id, u.username, u.email, dp.blood_type 
            FROM users u
            LEFT JOIN donor_profiles dp ON u.id = dp.user_id
            WHERE u.role = 'donor'
            ORDER BY u.username
        ''')
        
        donors = cursor.fetchall()
        cursor.close()
        
        return jsonify(donors)
    
    except Exception as e:
        print(f"Error fetching donors: {e}")
        return jsonify({"error": "Unable to fetch donors"}), 500

@app.route("/api/donors/<int:donor_id>", methods=["DELETE"])
@login_required
def delete_donor(donor_id):
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor()
        
        # First check if the donor exists
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', (donor_id, "donor"))
        donor = cursor.fetchone()
        
        if not donor:
            cursor.close()
            return jsonify({"success": False, "message": "Donor not found"}), 404
        
        # Delete from donor_profiles first (due to foreign key)
        cursor.execute('DELETE FROM donor_profiles WHERE user_id = %s', (donor_id,))
        
        # Then delete from users table
        cursor.execute('DELETE FROM users WHERE id = %s', (donor_id,))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True, "message": "Donor deleted successfully"})
    
    except Exception as e:
        print(f"Error deleting donor: {e}")
        return jsonify({"error": f"Unable to delete donor: {str(e)}"}), 500

@app.route("/api/hospitals", methods=["GET"])
@login_required
def get_hospitals():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Join users and hospital_profiles tables to get complete hospital info
        cursor.execute('''
            SELECT h.id, u.id as user_id, u.username, u.email, h.hospital_name, h.address
            FROM hospital_profiles h
            JOIN users u ON h.user_id = u.id
            WHERE u.role = 'hospital'
        ''')
        
        hospitals = cursor.fetchall()
        cursor.close()
        
        return jsonify(hospitals)
    
    except Exception as e:
        print(f"Error fetching hospitals: {e}")
        return jsonify({"success": False, "message": "Failed to fetch hospitals"}), 500

@app.route("/api/hospitals/<int:hospital_id>", methods=["DELETE"])
@login_required
def delete_hospital(hospital_id):
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    try:
        cursor = mysql.connection.cursor()
        
        # First get the user_id associated with this hospital profile
        cursor.execute('SELECT user_id FROM hospital_profiles WHERE id = %s', (hospital_id,))
        result = cursor.fetchone()
        
        if not result:
            cursor.close()
            return jsonify({"success": False, "message": "Hospital not found"}), 404
        
        user_id = result[0]
        
        # Delete cascade - first delete from related tables
        cursor.execute('DELETE FROM notifications WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM appointments WHERE hospital_id = %s', (user_id,))
        cursor.execute('DELETE FROM hospital_profiles WHERE id = %s', (hospital_id,))
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True, "message": "Hospital deleted successfully"})
    
    except Exception as e:
        print(f"Error deleting hospital: {e}")
        return jsonify({"success": False, "message": f"Failed to delete hospital: {str(e)}"}), 500

# ========================== RUN APP ==========================
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)