from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from datetime import datetime
import sqlite3
import bcrypt
import os
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from html import escape
from flask_limiter import RateLimitExceeded

# Get remaining attempts
def get_remaining_attempts(endpoint):
    limiter_obj = app.view_functions[endpoint].view_class if hasattr(app.view_functions[endpoint], 'view_class') else None
    limit = None
    if limiter_obj:
        # For class-based views (not used here)
        pass
    else:
        # For function views
        func = app.view_functions[endpoint]
        limit = getattr(func, "_limiter", None)
    
    if not limit:
        return None
    
    # Get current rate limit state
    try:
        remaining = limit.get_remaining(get_remote_address())
        total = limit._limit
        return {
            "remaining": remaining,
            "total": total,
            "reset_in": limit.get_expires() - int(datetime.now().timestamp()) if limit.get_expires() else None
        }
    except:
        return None


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "6 per hour"],
    storage_uri="memory://"
)
# Disable HTTPS enforcement for local development
Talisman(app, 
         force_https=False,
         content_security_policy={
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
    'img-src': "'self' data:",
    'font-src': "'self' https://cdnjs.cloudflare.com",
})

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User:
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
    
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return User(user[0], user[1], user[2]) if user else None

# Role-based access decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('Access denied. Insufficient permissions.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Users table with role
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, 
                  username TEXT UNIQUE, 
                  password TEXT, 
                  role TEXT,
                  email TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Patients table
    c.execute('''CREATE TABLE IF NOT EXISTS patients 
                 (id INTEGER PRIMARY KEY, 
                  user_id INTEGER,
                  name TEXT, 
                  dob TEXT, 
                  blood_type TEXT,
                  phone TEXT,
                  address TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Doctors table
    c.execute('''CREATE TABLE IF NOT EXISTS doctors 
                 (id INTEGER PRIMARY KEY, 
                  user_id INTEGER,
                  name TEXT,
                  specialization TEXT,
                  license_number TEXT,
                  phone TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Nurses table
    c.execute('''CREATE TABLE IF NOT EXISTS nurses 
                 (id INTEGER PRIMARY KEY, 
                  user_id INTEGER,
                  name TEXT,
                  license_number TEXT,
                  phone TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Appointments table
    c.execute('''CREATE TABLE IF NOT EXISTS appointments 
                 (id INTEGER PRIMARY KEY, 
                  patient_id INTEGER,
                  doctor_id INTEGER,
                  appointment_date TEXT,
                  appointment_time TEXT,
                  status TEXT,
                  reason TEXT,
                  notes TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(patient_id) REFERENCES patients(id),
                  FOREIGN KEY(doctor_id) REFERENCES doctors(id))''')
    
    # Medical records table
    c.execute('''CREATE TABLE IF NOT EXISTS medical_records 
                 (id INTEGER PRIMARY KEY, 
                  patient_id INTEGER,
                  doctor_id INTEGER,
                  diagnosis TEXT,
                  prescription TEXT,
                  notes TEXT,
                  record_date TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(patient_id) REFERENCES patients(id),
                  FOREIGN KEY(doctor_id) REFERENCES doctors(id))''')
    
    # Medications table
    c.execute('''CREATE TABLE IF NOT EXISTS medications 
                 (id INTEGER PRIMARY KEY, 
                  patient_id INTEGER,
                  medication_name TEXT,
                  dosage TEXT,
                  frequency TEXT,
                  start_date TEXT,
                  end_date TEXT,
                  prescribed_by INTEGER,
                  FOREIGN KEY(patient_id) REFERENCES patients(id),
                  FOREIGN KEY(prescribed_by) REFERENCES doctors(id))''')
    
    # Medication logs table
    c.execute('''CREATE TABLE IF NOT EXISTS medication_logs 
                 (id INTEGER PRIMARY KEY, 
                  medication_id INTEGER,
                  administered_by INTEGER,
                  administered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  notes TEXT,
                  FOREIGN KEY(medication_id) REFERENCES medications(id),
                  FOREIGN KEY(administered_by) REFERENCES nurses(id))''')
    
    # Create default admin account
    # Create audit log table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log 
                (id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

def log_audit(user_id, action, details, ip_address):
    """Log security-sensitive actions"""
    conn = sqlite3.connect(os.getenv('DATABASE_URL', 'database.db'))
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
              (user_id, action, details, ip_address))
    conn.commit()
    conn.close()

# Input Validation and sanitization
def validate_and_sanitize(data, field_type='text'):
    """Validate and sanitize user input"""
    if not data:
        return None
    
    data = escape(data.strip())
    
    if field_type == 'username':
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', data):
            raise ValueError("Username must be 3-20 alphanumeric characters")
    elif field_type == 'email':
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data):
            raise ValueError("Invalid email format")
    elif field_type == 'password':
        if len(data) < 8 or not re.search(r'[A-Z]', data) or not re.search(r'[a-z]', data) or not re.search(r'[0-9]', data):
            raise ValueError("Password must be 8+ characters with uppercase, lowercase, and numbers")
    
    return data

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'nurse':
            return redirect(url_for('nurse_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Get current rate-limit status to show remaining attempts
    limit_info = None
    try:
        limiter.check()
        rv = limiter._storage.get(f"ratelimit/{request.endpoint}/{get_remote_address()}")
        if rv:
            remaining = rv[0] if rv[0] > 0 else 0
            reset_time = rv[2]
            limit_info = {
                "remaining": remaining,
                "total": 5,
                "reset_in": max(0, int(reset_time - datetime.utcnow().timestamp())) if reset_time else None
            }
    except Exception:
        pass

    if request.method == 'POST':
        try:
            username = validate_and_sanitize(request.form.get('username', ''), 'username')
            password = request.form.get('password', '')

            # Password strength validation
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return render_template('register.html', limit_info=limit_info)
            if not re.search(r'[A-Z]', password):
                flash('Password must contain at least one uppercase letter', 'danger')
                return render_template('register.html', limit_info=limit_info)
            if not re.search(r'[a-z]', password):
                flash('Password must contain at least one lowercase letter', 'danger')
                return render_template('register.html', limit_info=limit_info)
            if not re.search(r'[0-9]', password):
                flash('Password must contain at least one number', 'danger')
                return render_template('register.html', limit_info=limit_info)

            conn = sqlite3.connect(os.getenv('DATABASE_URL', 'database.db'))
            c = conn.cursor()

            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                      (username, hashed, 'patient', f'{username}@patient.com'))
            user_id = c.lastrowid

            c.execute("INSERT INTO patients (user_id, name, dob, blood_type, phone, address) VALUES (?, ?, ?, ?, ?, ?)",
                      (user_id, username, '2000-01-01', 'O+', 'N/A', 'N/A'))

            conn.commit()
            conn.close()

            log_audit(user_id, 'REGISTER', f'New patient account created: {username}', request.remote_addr)
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            # This catches RateLimitExceeded and any other unexpected error
            if "rate limit" in str(e).lower():
                flash('Too many registration attempts. Please try again later.', 'danger')
            else:
                flash('An error occurred. Please try again.', 'danger')

        # Re-calculate limit_info after a failed attempt
        try:
            limiter.check()
            rv = limiter._storage.get(f"ratelimit/{request.endpoint}/{get_remote_address()}")
            if rv:
                remaining = rv[0] if rv[0] > 0 else 0
                reset_time = rv[2]
                limit_info = {
                    "remaining": remaining,
                    "total": 5,
                    "reset_in": max(0, int(reset_time - datetime.utcnow().timestamp())) if reset_time else None
                }
        except:
            pass

    return render_template('register.html', limit_info=limit_info)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Get remaining attempts info
    limit_info = get_remaining_attempts('login')
    
    if request.method == 'POST':
        try:
            username = validate_and_sanitize(request.form.get('username', ''), 'username')
            password = request.form.get('password', '')

            conn = sqlite3.connect(os.getenv('DATABASE_URL', 'database.db'))
            c = conn.cursor()
            c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
            user_row = c.fetchone()
            conn.close()
            
            if user_row and bcrypt.checkpw(password.encode(), user_row[2]):
                user = User(user_row[0], user_row[1], user_row[3])
                login_user(user)
                log_audit(user.id, 'LOGIN', 'Successful login', request.remote_addr)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('index'))
            
            log_audit(None, 'FAILED_LOGIN', f'Failed login attempt for username: {username}', request.remote_addr)
            flash('Invalid credentials', 'danger')
            # Re-fetch limit info after failed attempt
            limit_info = get_remaining_attempts('login')
        
        except ValueError as e:
            flash(str(e), 'danger')
        except RateLimitExceeded:
            flash('Too many login attempts. Please try again later.', 'danger')
            limit_info = get_remaining_attempts('login')

    return render_template('login.html', limit_info=limit_info)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# ============== ADMIN ROUTES ==============
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute("SELECT COUNT(*) FROM users WHERE role='patient'")
    total_patients = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM users WHERE role='doctor'")
    total_doctors = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM users WHERE role='nurse'")
    total_nurses = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM appointments WHERE status='scheduled'")
    upcoming_appointments = c.fetchone()[0]
    
    # Get recent users
    c.execute("""SELECT u.id, u.username, u.role, u.email, u.created_at 
                 FROM users u ORDER BY u.created_at DESC LIMIT 10""")
    recent_users = c.fetchall()
    
    conn.close()
    
    return render_template('admin/admin_dashboard.html',
                         total_patients=total_patients,
                         total_doctors=total_doctors,
                         total_nurses=total_nurses,
                         upcoming_appointments=upcoming_appointments,
                         recent_users=recent_users)

@app.route('/admin/create_account', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_account():
    if request.method == 'POST':
        try:
            username = validate_and_sanitize(request.form.get('username', ''), 'username')
            password = request.form.get('password', '')
            role = request.form.get('role', '')
            email = validate_and_sanitize(request.form.get('email', ''), 'email')
            name = validate_and_sanitize(request.form.get('name', ''))
            
            # Validate password
            if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
                flash('Password must be 8+ characters with uppercase, lowercase, and numbers', 'danger')
                return redirect(url_for('create_account'))
                
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('create_account'))
                
        if role not in ['patient', 'doctor', 'nurse']:
            flash('Invalid role selected', 'danger')
            return redirect(url_for('create_account'))
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            # Create user account
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                     (username, hashed, role, email))
            user_id = c.lastrowid
            
            # Create role-specific entry
            if role == 'patient':
                dob = request.form.get('dob', '')
                blood_type = request.form.get('blood_type', '')
                phone = request.form.get('phone', '')
                address = request.form.get('address', '')
                c.execute("INSERT INTO patients (user_id, name, dob, blood_type, phone, address) VALUES (?, ?, ?, ?, ?, ?)",
                         (user_id, name, dob, blood_type, phone, address))
            
            elif role == 'doctor':
                specialization = request.form.get('specialization', '')
                license_number = request.form.get('license_number', '')
                phone = request.form.get('phone', '')
                c.execute("INSERT INTO doctors (user_id, name, specialization, license_number, phone) VALUES (?, ?, ?, ?, ?)",
                         (user_id, name, specialization, license_number, phone))
            
            elif role == 'nurse':
                license_number = request.form.get('license_number', '')
                phone = request.form.get('phone', '')
                c.execute("INSERT INTO nurses (user_id, name, license_number, phone) VALUES (?, ?, ?, ?)",
                         (user_id, name, license_number, phone))
            
            conn.commit()
            flash(f'{role.capitalize()} account created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        finally:
            conn.close()
    
    return render_template('admin/create_account.html')

# ============== PATIENT ROUTES ==============
@app.route('/patient/dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get patient info
    c.execute("SELECT id, name, dob, blood_type, phone FROM patients WHERE user_id = ?", (current_user.id,))
    patient = c.fetchone()
    
    if not patient:
        flash('Patient profile not found', 'danger')
        return redirect(url_for('index'))
    
    patient_id = patient[0]
    
    # Get upcoming appointments
    c.execute("""SELECT a.id, a.appointment_date, a.appointment_time, a.reason, 
                        d.name as doctor_name, d.specialization
                 FROM appointments a
                 JOIN doctors d ON a.doctor_id = d.id
                 WHERE a.patient_id = ? AND a.status = 'scheduled'
                 ORDER BY a.appointment_date, a.appointment_time""", (patient_id,))
    appointments = c.fetchall()
    
    # Get recent medical records
    c.execute("""SELECT mr.id, mr.diagnosis, mr.record_date, d.name as doctor_name
                 FROM medical_records mr
                 JOIN doctors d ON mr.doctor_id = d.id
                 WHERE mr.patient_id = ?
                 ORDER BY mr.record_date DESC LIMIT 5""", (patient_id,))
    records = c.fetchall()
    
    # Get active medications
    c.execute("""SELECT m.medication_name, m.dosage, m.frequency, m.start_date, m.end_date
                 FROM medications m
                 WHERE m.patient_id = ? AND m.end_date >= date('now')
                 ORDER BY m.start_date DESC""", (patient_id,))
    medications = c.fetchall()
    
    conn.close()
    
    return render_template('patient/patient_dashboard.html',
                         patient=patient,
                         appointments=appointments,
                         records=records,
                         medications=medications)

@app.route('/patient/appointments')
@login_required
@role_required('patient')
def patient_appointments():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM patients WHERE user_id = ?", (current_user.id,))
    patient = c.fetchone()
    
    if patient:
        patient_id = patient[0]
        c.execute("""SELECT a.id, a.appointment_date, a.appointment_time, a.reason, 
                            a.status, a.notes, d.name as doctor_name, d.specialization
                     FROM appointments a
                     JOIN doctors d ON a.doctor_id = d.id
                     WHERE a.patient_id = ?
                     ORDER BY a.appointment_date DESC, a.appointment_time DESC""", (patient_id,))
        appointments = c.fetchall()
    else:
        appointments = []
    
    # Get all doctors for booking
    c.execute("SELECT id, name, specialization FROM doctors ORDER BY name")
    doctors = c.fetchall()
    
    conn.close()
    return render_template('patient/appointments.html', appointments=appointments, doctors=doctors)

@app.route('/patient/book_appointment', methods=['POST'])
@login_required
@role_required('patient')
def book_appointment():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM patients WHERE user_id = ?", (current_user.id,))
    patient = c.fetchone()
    
    if patient:
        patient_id = patient[0]
        doctor_id = request.form.get('doctor_id')
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')
        
        c.execute("""INSERT INTO appointments 
                     (patient_id, doctor_id, appointment_date, appointment_time, status, reason)
                     VALUES (?, ?, ?, ?, 'scheduled', ?)""",
                  (patient_id, doctor_id, appointment_date, appointment_time, reason))
        conn.commit()
        flash('Appointment booked successfully!', 'success')
    
    conn.close()
    return redirect(url_for('patient_appointments'))

@app.route('/patient/medical_records')
@login_required
@role_required('patient')
def patient_medical_records():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM patients WHERE user_id = ?", (current_user.id,))
    patient = c.fetchone()
    
    if patient:
        patient_id = patient[0]
        c.execute("""SELECT mr.id, mr.diagnosis, mr.prescription, mr.notes, 
                            mr.record_date, d.name as doctor_name, d.specialization
                     FROM medical_records mr
                     JOIN doctors d ON mr.doctor_id = d.id
                     WHERE mr.patient_id = ?
                     ORDER BY mr.record_date DESC""", (patient_id,))
        records = c.fetchall()
    else:
        records = []
    
    conn.close()
    return render_template('patient/medical_records.html', records=records)

# ============== DOCTOR ROUTES ==============
@app.route('/doctor/dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get doctor info
    c.execute("SELECT id, name, specialization FROM doctors WHERE user_id = ?", (current_user.id,))
    doctor = c.fetchone()
    
    if not doctor:
        flash('Doctor profile not found', 'danger')
        return redirect(url_for('index'))
    
    doctor_id = doctor[0]
    
    # Get today's appointments
    c.execute("""SELECT a.id, a.appointment_time, a.reason, p.name as patient_name
                 FROM appointments a
                 JOIN patients p ON a.patient_id = p.id
                 WHERE a.doctor_id = ? AND a.appointment_date = date('now') 
                 AND a.status = 'scheduled'
                 ORDER BY a.appointment_time""", (doctor_id,))
    today_appointments = c.fetchall()
    
    # Get total patients count
    c.execute("""SELECT COUNT(DISTINCT patient_id) FROM appointments 
                 WHERE doctor_id = ?""", (doctor_id,))
    total_patients = c.fetchone()[0]
    
    # Get upcoming appointments count
    c.execute("""SELECT COUNT(*) FROM appointments 
                 WHERE doctor_id = ? AND status = 'scheduled' 
                 AND appointment_date >= date('now')""", (doctor_id,))
    upcoming_count = c.fetchone()[0]
    
    conn.close()
    
    return render_template('doctor/doctor_dashboard.html',
                         doctor=doctor,
                         today_appointments=today_appointments,
                         total_patients=total_patients,
                         upcoming_count=upcoming_count)

@app.route('/doctor/patients')
@login_required
@role_required('doctor')
def doctor_patients():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM doctors WHERE user_id = ?", (current_user.id,))
    doctor = c.fetchone()
    
    if doctor:
        doctor_id = doctor[0]
        c.execute("""SELECT DISTINCT p.id, p.name, p.dob, p.blood_type, p.phone
                     FROM patients p
                     JOIN appointments a ON p.id = a.patient_id
                     WHERE a.doctor_id = ?
                     ORDER BY p.name""", (doctor_id,))
        patients = c.fetchall()
    else:
        patients = []
    
    conn.close()
    return render_template('doctor/patients_list.html', patients=patients)

@app.route('/doctor/patient/<int:patient_id>')
@login_required
@role_required('doctor')
def doctor_patient_detail(patient_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get patient info
    c.execute("SELECT id, name, dob, blood_type, phone, address FROM patients WHERE id = ?", (patient_id,))
    patient = c.fetchone()
    
    # Get medical records
    c.execute("""SELECT id, diagnosis, prescription, notes, record_date
                 FROM medical_records
                 WHERE patient_id = ?
                 ORDER BY record_date DESC""", (patient_id,))
    records = c.fetchall()
    
    # Get medications
    c.execute("""SELECT medication_name, dosage, frequency, start_date, end_date
                 FROM medications
                 WHERE patient_id = ?
                 ORDER BY start_date DESC""", (patient_id,))
    medications = c.fetchall()
    
    conn.close()
    return render_template('doctor/patient_record_detail.html',
                         patient=patient,
                         records=records,
                         medications=medications)

@app.route('/doctor/add_record/<int:patient_id>', methods=['POST'])
@login_required
@role_required('doctor')
def add_medical_record(patient_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM doctors WHERE user_id = ?", (current_user.id,))
    doctor = c.fetchone()
    
    if doctor:
        doctor_id = doctor[0]
        diagnosis = request.form.get('diagnosis')
        prescription = request.form.get('prescription')
        notes = request.form.get('notes')
        record_date = request.form.get('record_date')
        
        c.execute("""INSERT INTO medical_records 
                     (patient_id, doctor_id, diagnosis, prescription, notes, record_date)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (patient_id, doctor_id, diagnosis, prescription, notes, record_date))
        conn.commit()
        flash('Medical record added successfully!', 'success')
    
    conn.close()
    return redirect(url_for('doctor_patient_detail', patient_id=patient_id))

@app.route('/doctor/prescribe_medication/<int:patient_id>', methods=['POST'])
@login_required
@role_required('doctor')
def prescribe_medication(patient_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM doctors WHERE user_id = ?", (current_user.id,))
    doctor = c.fetchone()
    
    if doctor:
        doctor_id = doctor[0]
        medication_name = request.form.get('medication_name')
        dosage = request.form.get('dosage')
        frequency = request.form.get('frequency')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        
        c.execute("""INSERT INTO medications 
                     (patient_id, medication_name, dosage, frequency, start_date, end_date, prescribed_by)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (patient_id, medication_name, dosage, frequency, start_date, end_date, doctor_id))
        conn.commit()
        flash('Medication prescribed successfully!', 'success')
    
    conn.close()
    return redirect(url_for('doctor_patient_detail', patient_id=patient_id))

@app.route('/doctor/appointments')
@login_required
@role_required('doctor')
def doctor_appointments():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM doctors WHERE user_id = ?", (current_user.id,))
    doctor = c.fetchone()
    
    if doctor:
        doctor_id = doctor[0]
        c.execute("""SELECT a.id, a.appointment_date, a.appointment_time, 
                            a.reason, a.status, p.name as patient_name
                     FROM appointments a
                     JOIN patients p ON a.patient_id = p.id
                     WHERE a.doctor_id = ?
                     ORDER BY a.appointment_date DESC, a.appointment_time DESC""", (doctor_id,))
        appointments = c.fetchall()
    else:
        appointments = []
    
    conn.close()
    return render_template('doctor/appointments_schedule.html', appointments=appointments)

# ============== NURSE ROUTES ==============
@app.route('/nurse/dashboard')
@login_required
@role_required('nurse')
def nurse_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get nurse info
    c.execute("SELECT id, name FROM nurses WHERE user_id = ?", (current_user.id,))
    nurse = c.fetchone()
    
    if not nurse:
        flash('Nurse profile not found', 'danger')
        return redirect(url_for('index'))
    
    nurse_id = nurse[0]
    
    # Get today's medication count
    c.execute("""SELECT COUNT(*) FROM medications 
                 WHERE start_date <= date('now') AND end_date >= date('now')""")
    active_medications = c.fetchone()[0]
    
    # Get today's administered medications
    c.execute("""SELECT COUNT(*) FROM medication_logs 
                 WHERE administered_by = ? AND date(administered_at) = date('now')""", (nurse_id,))
    administered_today = c.fetchone()[0]
    
    conn.close()
    
    return render_template('nurse/nurse_dashboard.html',
                         nurse=nurse,
                         active_medications=active_medications,
                         administered_today=administered_today)

@app.route('/nurse/medications')
@login_required
@role_required('nurse')
def nurse_medications():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get all active medications with patient info
    c.execute("""SELECT m.id, p.name as patient_name, m.medication_name, 
                        m.dosage, m.frequency, m.start_date, m.end_date
                 FROM medications m
                 JOIN patients p ON m.patient_id = p.id
                 WHERE m.end_date >= date('now')
                 ORDER BY p.name, m.medication_name""")
    medications = c.fetchall()
    
    conn.close()
    return render_template('nurse/medication_schedule.html', medications=medications)

@app.route('/nurse/administer/<int:medication_id>', methods=['POST'])
@login_required
@role_required('nurse')
def administer_medication(medication_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT id FROM nurses WHERE user_id = ?", (current_user.id,))
    nurse = c.fetchone()
    
    if nurse:
        nurse_id = nurse[0]
        notes = request.form.get('notes', '')
        
        c.execute("""INSERT INTO medication_logs (medication_id, administered_by, notes)
                     VALUES (?, ?, ?)""", (medication_id, nurse_id, notes))
        conn.commit()
        flash('Medication administered successfully', 'success')
    
    conn.close()
    return redirect(url_for('nurse_medications'))

if __name__ == '__main__':
    init_db()
    
    # Production settings
    if os.getenv('FLASK_ENV') == 'production':
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        # Force HTTPS in production
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 5001)),
        debug=os.getenv('FLASK_ENV') != 'production'
    )