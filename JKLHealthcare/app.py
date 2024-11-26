from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SECRET_KEY'] = '123'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'caregiver', 'patient'

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    medical_records = db.Column(db.Text, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('patient', uselist=False))
    appointments = db.relationship('Appointment', backref='patient', lazy=True)

class Caregiver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    availability = db.Column(db.Boolean, default=True)
    gender = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('caregiver', uselist=False))
    assignments = db.relationship('Assignment', backref=db.backref('assignment_caregiver', lazy=True))  # Changed backref name

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    caregiver_id = db.Column(db.Integer, db.ForeignKey('caregiver.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    patient = db.relationship('Patient', backref=db.backref('assignments', lazy=True))
    caregiver = db.relationship('Caregiver', backref=db.backref('caregiver_assignments', lazy=True))  # Changed backref name


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    caregiver_id = db.Column(db.Integer, db.ForeignKey('caregiver.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='Scheduled')  # Scheduled, Completed, Cancelled

# Initialize database on app startup
with app.app_context():
    db.create_all()

# Routes for User Registration and Login
@app.route('/')
def home():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session['role'] == 'caregiver':
            return redirect(url_for('caregiver_dashboard'))
        elif session['role'] == 'patient':
            return redirect(url_for('patient_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!')
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for(f'{user.role}_dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('login'))


# Patient Dashboard

@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user_id' not in session or session.get('role') != 'patient':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()

    return render_template('patient_dashboard.html', patient=patient, appointments=appointments)


@app.route('/edit_patient_info', methods=['GET', 'POST'])
def edit_patient_info():
    if 'user_id' not in session or session.get('role') != 'patient':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    patient = Patient.query.filter_by(user_id=session['user_id']).first()

    if request.method == 'POST':
        patient.name = request.form['name']
        patient.address = request.form['address']
        patient.medical_records = request.form['medical_records']
        patient.phone = request.form['phone']
        patient.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
        patient.gender = request.form['gender']

        db.session.commit()
        flash('Your information has been updated!', 'success')
        return redirect(url_for('patient_dashboard'))

    return render_template('edit_patient_info.html', patient=patient)


# Caregiver Assignment Dashboard

@app.route('/assign_caregiver/<int:patient_id>', methods=['GET', 'POST'])
def assign_caregiver(patient_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    patient = Patient.query.get_or_404(patient_id)
    caregivers = Caregiver.query.all()

    if request.method == 'POST':
        caregiver_id = request.form['caregiver_id']
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%d %H:%M:%S')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%d %H:%M:%S')

        caregiver = Caregiver.query.get(caregiver_id)

        if caregiver.availability:
            new_assignment = Assignment(patient_id=patient.id, caregiver_id=caregiver.id, start_time=start_time, end_time=end_time)
            caregiver.availability = False  # Mark caregiver as unavailable
            db.session.add(new_assignment)
            db.session.commit()
            flash('Caregiver assigned successfully!', 'success')
        else:
            flash('Caregiver is not available at this time.', 'danger')

        return redirect(url_for('admin_dashboard'))

    return render_template('assign_caregiver.html', patient=patient, caregivers=caregivers)


@app.route('/remove_assignment/<int:assignment_id>')
def remove_assignment(assignment_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    assignment = Assignment.query.get_or_404(assignment_id)
    caregiver = Caregiver.query.get(assignment.caregiver_id)
    caregiver.availability = True  # Mark caregiver as available again

    db.session.delete(assignment)
    db.session.commit()

    flash('Assignment removed successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# Appointment Scheduling

@app.route('/schedule_appointment/<int:patient_id>', methods=['GET', 'POST'])
def schedule_appointment(patient_id):
    if 'user_id' not in session or session.get('role') != 'caregiver':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    patient = Patient.query.get_or_404(patient_id)

    if request.method == 'POST':
        appointment_time = datetime.strptime(request.form['appointment_time'], '%Y-%m-%d %H:%M:%S')

        appointment = Appointment(patient_id=patient.id, caregiver_id=session['user_id'], appointment_time=appointment_time)
        db.session.add(appointment)
        db.session.commit()

        flash('Appointment scheduled successfully!', 'success')
        return redirect(url_for('caregiver_dashboard'))

    return render_template('schedule_appointment.html', patient=patient)


@app.route('/update_appointment/<int:appointment_id>', methods=['GET', 'POST'])
def update_appointment(appointment_id):
    if 'user_id' not in session or session.get('role') != 'caregiver':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    appointment = Appointment.query.get_or_404(appointment_id)

    if request.method == 'POST':
        appointment.status = request.form['status']
        db.session.commit()

        flash('Appointment status updated!', 'success')
        return redirect(url_for('caregiver_dashboard'))

    return render_template('update_appointment.html', appointment=appointment)


# Admin Dashboard

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    patients = Patient.query.all()
    caregivers = Caregiver.query.all()

    return render_template('admin_dashboard.html', patients=patients, caregivers=caregivers)


if __name__ == "__main__":
    app.run(debug=True)
