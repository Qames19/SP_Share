from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import jsonify
import hashlib
import os
import sqlite3

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

connect = sqlite3.connect('database.db')
connect.execute(
        'CREATE TABLE IF NOT EXISTS USERS (fname TEXT, \
        lname TEXT, username TEXT, email TEXT, nacl TEXT,\
        password TEXT)')

@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/welcome')
def welcome():
    if Session:
        return render_template("welcome.html")
    return render_template("welcome.html", username="Please login to see content")

@app.route('/join', methods=['GET', 'POST'])
def join():
    if request.method == 'POST':
        first_name  = request.form['first-name']
        last_name   = request.form['last-name']
        username    = request.form['user-name']
        email       = request.form['e-mail']
        salt        = os.urandom(32)
        h_password  = hashlib.pbkdf2_hmac('sha256', request.form['passwd'].encode('utf-8'), salt, 100000)

        if request.form['passwd'] != request.form['passwd-conf']:
            return render_template("join.html", invalid_password="true")
        if not user_exists(username, email):
            with sqlite3.connect("database.db") as users:
                cursor= users.cursor()
                cursor.execute("INSERT INTO USERS \
                                (fname, lname, username, email, nacl, password) VALUES (?,?,?,?,?,?)",
                                (first_name, last_name, username, email, salt, h_password))
                users.commit()
            return render_template("index.html")
        else:
            return render_template('join.html', invalid_entry="true")
    return render_template('join.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['user-name']
        connect = sqlite3.connect('database.db')
        cursor = connect.cursor()

        query = "SELECT * FROM USERS WHERE username = ?"
        data = cursor.execute(query, (username,))

        if data:
            query = "SELECT password FROM USERS WHERE username = ?"
            h_password = cursor.execute(query, (username,)).fetchone()[0]
            query = "SELECT nacl FROM USERS WHERE username = ?"
            salt = cursor.execute(query, (username,)).fetchone()[0]
            check_password = hashlib.pbkdf2_hmac('sha256', request.form['passwd'].encode('utf-8'), salt, 100000)
            if h_password == check_password:
                session["name"] = request.form.get("user-name")
                return render_template('welcome.html', username=session["name"])
            message = "UNABLE TO AUTHENTICATE"
            return render_template("error.html", message=message)
        message = "UNABLE TO AUTHENTICATE"
        return render_template("error.html", message=message)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/home")

@app.route('/oops')
def error():
    return render_template("error.html", message="What is you looking for?")

def user_exists(username, email):
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    query = "SELECT * FROM USERS WHERE username = ? OR email = ?"
    cursor.execute(query, (username, email))

    result = cursor.fetchone()
    connection.close()

    return result != None


if __name__ == '__main__':
    app.run(debug=False)

