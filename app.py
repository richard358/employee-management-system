from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import psycopg2
import pandas as pd
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        database=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        port=os.environ.get("DB_PORT", 5432)
    )

@app.route('/')
def home():
    return redirect(url_for('dashboard') if 'user' in session else 'login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password, role FROM users WHERE username=%s", (username,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            session['user'] = username
            session['role'] = result[1]
            flash("Login successful.")
            return redirect(url_for('dashboard'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM data")
    employees = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('index.html', employees=employees, role=session.get('role'))

@app.route('/add', methods=['POST'])
def add():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    id = request.form['id']
    name = request.form['name']
    phone = request.form['phone']
    role = request.form['role']
    gender = request.form['gender']
    salary = request.form['salary']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO data (id, name, phone, role, gender, salary) VALUES (%s, %s, %s, %s, %s, %s)",
                (id, name, phone, role, gender, salary))
    conn.commit()
    cur.close()
    conn.close()
    flash("Employee added successfully.")
    return redirect(url_for('dashboard'))

@app.route('/update', methods=['POST'])
def update():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    id = request.form['id']
    name = request.form['name']
    phone = request.form['phone']
    role = request.form['role']
    gender = request.form['gender']
    salary = request.form['salary']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE data SET name=%s, phone=%s, role=%s, gender=%s, salary=%s WHERE id=%s",
                (name, phone, role, gender, salary, id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Employee updated successfully.")
    return redirect(url_for('dashboard'))

@app.route('/delete/<id>')
def delete(id):
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM data WHERE id=%s", (id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("Record deleted.")
    return redirect(url_for('dashboard'))

@app.route('/delete_all')
def delete_all():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("TRUNCATE TABLE data RESTART IDENTITY CASCADE")
    conn.commit()
    cur.close()
    conn.close()
    flash("All records deleted.")
    return redirect(url_for('dashboard'))

@app.route('/search')
def search():
    if 'user' not in session:
        return redirect(url_for('login'))
    option = request.args.get('option')
    value = request.args.get('value')
    if option not in ['id', 'name', 'phone', 'role', 'gender', 'salary']:
        flash("Invalid search option.")
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM data WHERE {option} ILIKE %s", (f'%{value}%',))
    employees = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('index.html', employees=employees, role=session.get('role'))

@app.route('/download_excel')
def download_excel():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM data")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    df = pd.DataFrame(rows, columns=['ID', 'Name', 'Phone', 'Role', 'Gender', 'Salary'])
    filepath = 'employee_data.xlsx'
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if session.get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                    (username, hashed_pw.decode('utf-8'), role))
        conn.commit()
    cur.execute("SELECT username, role FROM users")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/delete_user/<username>')
def delete_user(username):
    if session.get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    if username == session.get('user'):
        flash("You cannot delete your own admin account while logged in.")
        return redirect(url_for('manage_users'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=%s", (username,))
    conn.commit()
    cur.close()
    conn.close()
    flash(f"User '{username}' has been deleted.")
    return redirect(url_for('manage_users'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash("New passwords do not match.")
            return redirect(url_for('change_password'))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=%s", (session['user'],))
        result = cur.fetchone()
        if not result or not bcrypt.checkpw(current_password.encode('utf-8'), result[0].encode('utf-8')):
            flash("Current password is incorrect.")
            cur.close()
            conn.close()
            return redirect(url_for('change_password'))
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cur.execute("UPDATE users SET password=%s WHERE username=%s", (hashed_pw.decode('utf-8'), session['user']))
        conn.commit()
        cur.close()
        conn.close()
        flash("Password updated successfully.")
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)
