from flask import Flask, render_template, request, redirect, session, flash #get_flashed_messages
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt 
import re
from datetime import datetime

app = Flask(__name__)

bcrypt = Bcrypt(app)
app.secret_key = 'password login registration'

dbname = 'user_pw'

@app.route("/")
def mainpage():
    return render_template("index.html")

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
Password_num_regex = re.compile(r'.*[0-9]+.*')
Password_upper_regex = re.compile(r'.*[A-Z]+.*')


@app.route('/createUser', methods=['POST'])
def create():
    print("in create method: ", request.form)
    # include some logic to validate user input before adding them to the database!
    is_valid=True
    if not EMAIL_REGEX.match(request.form["email"]):
        flash("INVALID email address. Try again.", "email")
        is_valid=False
    if len(request.form['firstname'])<2:
        is_valid=False
        flash("First name needs to be at least 2 characters long.", "firstname")
    if len(request.form['lastname'])<2:
        is_valid=False
        flash("Last name needs to be at least 2 characters long.", "lastname")
    if len(request.form['password'])<8:
        is_valid=False
        flash("Password needs to be at least 8 characters.", "password")
    if (not Password_num_regex.match(request.form['password'])) or (not Password_upper_regex.match(request.form['password'])):
        is_valid= False
        flash("Must have one number and one upppercase character in password", "password")
    if (request.form['password']== "") or (request.form['password'] != request.form['confirm']):
        is_valid=False
        flash("Password must match!", "passwordconfirmation")
    if not is_valid:
        return redirect('/')
    
    mysql = connectToMySQL(dbname)
    email_unique = mysql.query_db("SELECT * FROM users WHERE email=%(email)s", request.form)
    print("is email in database?: ", email_unique)
    if len(email_unique) > 0:
        flash("This email is already taken.", "email")
        return redirect('/')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print("pw_hash:", pw_hash)  
        mysql = connectToMySQL(dbname)
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(user_first)s, %(user_last)s,%(user_em)s,%(passw_hash)s, NOW(), NOW());"
        # put the pw_hash in our data dictionary, NOT the password the user provided
        data = {
            "user_first" : request.form['firstname'],
            "user_last" : request.form['lastname'],
            "user_em" : request.form['email'],
            "passw_hash" : pw_hash
        }
        user_id = mysql.query_db(query, data)
        print("insert :", user_id)

        # check query has an id and is not () and False
        if user_id:
            session['id']=user_id
            session['firstname'] = request.form['firstname']
            print(" registration session: ", session)
            flash("Your registration was successful "+session['firstname']+ ". Welcome!", "registration")
            return redirect('/success')
        else:
            flash("There was a problem in the registration process on our side.Try later.","registerproblem")
            return redirect("/")

@app.route('/login', methods=['POST'])
def login():
    print("IN login:", request.form)
    # see if the email provided exists in the database
    mysql = connectToMySQL(dbname)
    result = mysql.query_db("SELECT * FROM users WHERE  email= %(user_email)s;", request.form)
    print("result of email check, in login method: ", result)
    if len(result) > 0:
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['user_password']):
            # if we get True put user id in session
            session['id'] = result[0]['id']
            session['firstname'] = result[0]['first_name']
            print("login session")
            flash("Your login was successful "+session['firstname'], "login")
            return redirect('/success')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("You could not be logged in", "notloggedin")
    return redirect("/")

@app.route('/success')
def display_login():
    #check if user is logged in
    if 'id' in session:
        print("IN success method: session is: ", session)
        return render_template("success.html")
    # if not logged in, direct user back to login page.
    else:
        flash("You need to be logged in.","mustlogin")
        return redirect('/')

@app.route('/clear')
def clear_session():
    session.clear()
    print("session should be empty: ", session)
    flash("You are logged out.", "logout")
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)