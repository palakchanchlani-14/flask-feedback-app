from flask import Flask, render_template, request, session, redirect, url_for, flash
from pymongo import MongoClient
import re
import random
import smtplib
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
from datetime import timezone

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client['CollegeFeedback']
feedback_collection = db['feedbacks']
users_collection = db['users']

# Function to send OTP for login security
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['otp_expire'] = True  
    print(f"Generated OTP: {otp}")  # ✅ Debugging step

    sender_email = os.getenv("SENDER_EMAIL")  
    app_password = os.getenv("EMAIL_PASSWORD")  

    if not sender_email or not app_password:
        print("Error: SMTP email or password not set!")
        return

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        message = f"Your OTP is {otp}. Enter it to complete authentication."
        server.sendmail(sender_email, email, message)
        server.quit()
        print(f"OTP email sent to {email}")  
    except Exception as e:
        print("Error sending OTP:", e)

# Validate College Email
def validate_ves_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@ves\.ac\.in$", email)

@app.route('/')
def home():
    return render_template('index.html')

# Admin Login (Restricted to Palak Only)
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == "palak" and password == "123":
            session['user'] = "admin"
            return redirect(url_for("admin_dashboard"))

        else:
            flash("Incorrect credentials! Only Palak can login as admin.", "danger")
    
    return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')  
        email = request.form['email']

        if not validate_ves_email(email):
            flash("Only college emails (@ves.ac.in) are allowed!", "danger")
            return redirect(url_for("register"))

        users_collection.insert_one({"username": username, "password": password, "email": email})
        flash("Registration Successful! Please login.", "success")
        return redirect(url_for("student_login"))
    
    return render_template('register.html')

# Student Login Requires OTP
@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')  
        user = users_collection.find_one({"email": email})

        if not user:
            flash("Email not registered! Please sign up first.", "danger")
            return redirect(url_for("register"))

        if not bcrypt.check_password_hash(user['password'], password):  
            flash("Incorrect password!", "danger")
            return redirect(url_for("student_login"))

        send_otp(email)  
        session["temp_email"] = email  

        users_collection.update_one({"email": email}, {"$set": {"last_login": datetime.now(timezone.utc)}})  # ✅ Corrected!

        return redirect(url_for("verify_student_otp"))

    return render_template("student_login.html")

@app.route('/verify_student_otp', methods=['GET', 'POST'])
def verify_student_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            session["user"] = session["temp_email"]
            session.pop("temp_email")
            return redirect(url_for("student_dashboard"))  
        else:
            flash("Incorrect OTP! Try again.", "danger")

    return render_template("verify_student_otp.html")

@app.route('/student_dashboard')
def student_dashboard():
    if 'user' not in session:
        return redirect(url_for("student_login"))

    return render_template("student_dashboard.html")  

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user' not in session or session['user'] == "admin":
        return redirect(url_for('student_login'))

    if request.method == 'POST':
        try:
            subject = request.form['subject']
            faculty = request.form['faculty']
            rating = int(request.form['rating'])
            comments = request.form.get('comments', '')  # ✅ Use `.get()` to prevent KeyError
            suggestions = request.form.get('suggestions', '')
            uploaded_file = request.files['file']

            file_path = f"static/uploads/{uploaded_file.filename}" if uploaded_file.filename else None
            if uploaded_file.filename:
                uploaded_file.save(file_path)

            existing_feedback = feedback_collection.find_one({"email": session['user'], "subject": subject})
            if existing_feedback:
                flash("You have already submitted feedback for this subject!", "warning")
                return redirect(url_for("feedback"))

            feedback_entry = {
                "subject": subject,
                "faculty": faculty,
                "rating": rating,
                "comments": comments,
                "suggestions": suggestions,
                "email": session["user"],
                "file_upload": file_path
            }
            feedback_collection.insert_one(feedback_entry)
            flash("Feedback submitted successfully!", "success")
            return redirect(url_for("feedback"))

        except KeyError as e:
            flash(f"Missing form field: {e}", "danger")
            return redirect(url_for("feedback"))

    return render_template('feedback.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' not in session or session['user'] != "admin":
        return redirect(url_for('admin_login'))

    feedbacks = list(feedback_collection.find().sort("subject"))
    students = list(users_collection.find({}, {"username": 1, "email": 1, "last_login": 1}))  

    return render_template("admin_dashboard.html", feedbacks=feedbacks, students=students)

@app.route('/search_feedback', methods=['GET'])
def search_feedback():
    if 'user' not in session or session['user'] != "admin":
        return redirect(url_for('admin_login'))

    query_subject = request.args.get('query', '').strip()
    sort_option = request.args.get('sort', 'latest')  
    sort_order = -1 if sort_option == "latest" else 1  

    feedbacks = list(feedback_collection.find(
        {"subject": {"$regex": f"^{re.escape(query_subject)}", "$options": "i"}}
    ).sort("subject", sort_order))

    return render_template("search_feedback.html", feedbacks=feedbacks, query=query_subject)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
