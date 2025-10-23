from flask import Flask, render_template, request, redirect, url_for, session,jsonify,flash
import mysql.connector
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

app = Flask(__name__)
app.secret_key = '123456789'

# Database connection
def get_db_connection():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='root',
        database='chotu'
    )
    return connection

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        admin_id = request.form['admin_id']
        admin_password = request.form['admin_password']

        # Fixed credentials (for demo purposes)
        if admin_id == 'admin' and admin_password == 'password123':
            return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
        else:
            return "Invalid credentials", 403  # Show an error

    return render_template('admin.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')  # Create this dashboard template

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        number = request.form['number']
        password = request.form['password']
        email = request.form['email']

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO yogi (username, password, email, firstname, lastname, number) VALUES (%s, %s, %s, %s, %s, %s)",
                       (username, password, email, firstname, lastname, number))
        connection.commit()
        cursor.close()
        connection.close()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM yogi WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and user[2] == password:  # Assuming plain text password comparison
            session['user_id'] = user[0]  # Store user ID in session
            session['email'] = email  # Optionally store email in session
            return redirect(url_for('search'))  # Redirect to the 'main' page
        else:
            error = "Invalid email or password"

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()  # Clear session data
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/main', methods=['GET'])
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    return render_template('index.html') 

@app.route('/insert_user_info', methods=['GET', 'POST'])
def insert_user_info():
    success_message = None  # Initialize success_message variable
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        phonenumber = request.form['phonenumber']
        profile_path = request.files['image']
        country=request.form['country']
        # Define upload folder and create it if it doesn't exist
        upload_folder = 'static/uploads'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Secure the filename and build the full path
        profile_filename = profile_path.filename
        pest_path = os.path.join(upload_folder, profile_filename).replace('\\', '/')

        # Save the file to the specified path
        profile_path.save(pest_path)

        # Prepare the relative path for storing in the database
        profile_path1 = os.path.join('static', 'uploads', profile_filename).replace('\\', '/')

        # Get the remaining form fields
        pincode = request.form['pincode']
        address = request.form['address']

        # Insert data into the database
        connection = get_db_connection()  # You need to have your DB connection function
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO user_info (firstname, lastname, email, phonenumber, pincode, address,country, profile) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (firstname, lastname, email, phonenumber, pincode, address,country, profile_path1)
        )

        connection.commit()
        cursor.close()
        connection.close()

        success_message = "User information successfully inserted."

    return render_template('insert_user_info.html', success_message=success_message)



@app.route('/search', methods=['GET','POST'])
def search():
    phone_number = request.form.get('phoneNumber')

    if not phone_number:
        return render_template('main.html', error="Please enter a phone number.")

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Include the 'profile' field in the query to fetch the profile picture path
        query = "SELECT firstname, lastname, phonenumber, country, pincode, address, email, profile FROM user_info WHERE phonenumber = %s"
        cursor.execute(query, (phone_number,))
        result = cursor.fetchone()

        cursor.close()
        connection.close()

        if result:
            return render_template('main.html', result=result)
        else:
            return render_template('main.html', error="No information found for this phone number.")

    except mysql.connector.Error as err:
        return render_template('main.html', error=f"Error: {err}")



@app.route('/users')
def users():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM yogi")
    all_users = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('users.html', users=all_users)
@app.route('/profiles')
def profiles():
    # Fetch data from the database
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT firstname, lastname, email, phonenumber, pincode, address, country, profile FROM user_info")
    users = cursor.fetchall()  # Fetch all records

    cursor.close()
    connection.close()

    # Render the template and pass the user data
    return render_template('profiles.html', users=users)


@app.route('/update_user', methods=['POST'])
def update_user():
    data = request.json
    print("Received data:", data)  # Debug print

    user_id = data['id']
    firstname = data['firstname']
    lastname = data['lastname']
    phonenumber = data['phonenumber']
    country = data['country']
    pincode = data['pincode']
    address = data['address']
    email = data['email']

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        update_query = """
            UPDATE user_info
            SET firstname = %s, lastname = %s, phonenumber = %s, country = %s, pincode = %s, address = %s, email = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (firstname, lastname, phonenumber, country, pincode, address, email, user_id))
        connection.commit()
        print("Update successful")  # Debug print

        cursor.close()
        connection.close()

        return jsonify({'success': True})
    except mysql.connector.Error as err:
        print("Update failed:", err)  # Debug print
        return jsonify({'success': False, 'error': str(err)})

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')  # Retrieve the email from session data

    if not email:
        flash("Session expired or email not found. Please try again.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        print(f"New Password: {new_password}, Confirm Password: {confirm_password}")  # Debugging
        print(f"Email from session: {email}")  # Debugging


        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('reset_password'))
            print("error")

        # Ensure the password meets your security requirements (e.g., length, complexity)
        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            print("error")
            return redirect(url_for('reset_password'))

        try:
            # Update the password in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE yogi SET password = %s WHERE email = %s", (new_password, email))
            conn.commit()
            print("password updated")
            

            # Clear the session data
            session.pop('reset_email', None)
            session.pop('reset_otp', None)

            flash("Your password has been successfully reset.", "success")
            return redirect(url_for('login'))  # Redirect to login page
            

        except mysql.connector.Error as err:
            print("success")
            flash(f"Database error: {err}", "error")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('reset_password.html', email=email)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM yogi WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Generate a password reset OTP or link
                otp = str(random.randint(100000, 999999))
                session['reset_email'] = email
                session['reset_otp'] = otp

                # Send the OTP or link to the user's email
                if send_otp_email(email, otp):
                    flash("A reset OTP has been sent to your email.", "success")
                    return render_template('verify_reset_otp.html')
                    #return redirect(url_for('verify_reset_otp'))  # Redirect to OTP verification page
                else:
                    flash("Failed to send reset email. Please try again.", "error")
            else:
                flash("Email not found in our records.", "error")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "error")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('forgot_password.html')

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    email = session.get('reset_email')  # Retrieve the email from session data

    if not email:
        flash("Session expired or email not found. Please try again.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if not entered_otp:
            flash("OTP is required.", "error")
            return redirect(url_for('verify_reset_otp'))

        if session.get('reset_otp') == entered_otp:
            flash("OTP verified successfully. You can now reset your password.", "success")
            return redirect(url_for('reset_password'))  # Redirect to the reset password page
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('verify_reset_otp.html', email=email)

def send_otp_email(email, otp):
    sender_email = "harishuppula33@gmail.com"  # Your Gmail address
    sender_password = "vypa jzvd ivmc bdzz"  # Your Gmail password
    receiver_email = email

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEMultipart()
    msg['From'] = "Profile Identification"
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return False


if __name__ == '__main__':
    app.run(debug=True)
    
  
