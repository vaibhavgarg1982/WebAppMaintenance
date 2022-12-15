from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    Response,
    send_from_directory,
    abort,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)

from werkzeug.security import generate_password_hash, check_password_hash

import os
import json

import sqlite3
import datetime
import time


app = Flask(__name__)
app.secret_key = "d9b98d29c818ee2e82b3b608c0d72257"

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    # get the user from the database
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    c.execute(
        "SELECT * FROM users WHERE email=?",
        (email,),
    )
    user = c.fetchone()
    conn.close()
    if user:
        role = user[3]
        active = user[4]
        user = User()
        user.id = email
        user.role = role
        user.active = active
        return user
    return None


@login_manager.request_loader
def request_loader(request):
    email = request.form.get("email")
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    c.execute(
        "SELECT * FROM users WHERE email=?",
        (email,),
    )
    user = c.fetchone()
    conn.close()
    if user:
        user = User()
        user.id = email
        return user
    return None


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    # get users from database, user table (username, hash))
    # username is the same as email
    email = request.form["email"]
    password = request.form["password"]
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    c.execute(
        "SELECT * FROM users WHERE email=?",
        (email,),
    )
    user = c.fetchone()
    conn.close()
    if user:
        if str(user[2]) == password:
            active = user[4]
            role = user[3]
            user = User()
            user.id = email
            user.role = role
            user.active = active
            login_user(user)
            # if user.role == "admin":
            #     return redirect(url_for("newuser"))
            return redirect(url_for("about"))
            # return render_template("about.html")  # redirect(url_for("projects"))

    return abort(401)


@app.route("/about", methods=["GET"])
@login_required
def about():
    # return "test"
    # redirect to AddComplaint
    return redirect(url_for("AddComplaint"))
    # return render_template("about.html")


@app.route("/AddComplaint", methods=["GET", "POST"])
@login_required
def AddComplaint():
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    if request.method == "POST":
        about = request.form["about"]
        complaint = request.form["Complaint"]
        # check for empty fields
        if about == "" or complaint == "":
            return render_template(
                "undercon.html",
                msg="Please fill in all fields. Press back and try again!",
            )
        # get the user_id from the users table, based on user email (current_user.id)
        c.execute(
            """
        select user_id from users where email = ?
        """,
            (current_user.id,),
        )
        user_id = c.fetchone()[0]
        # opentime as MMM-dd-yyyy HH:mm:ss
        opentime = time.strftime("%b-%d-%Y %H:%M:%S", time.localtime())
        # insert the complaint into the complaints table
        c.execute(
            """
        insert into complaints (user_id, about, complaint, status, opendate) values (?, ?, ?, ?, ?)
        """,
            (user_id, about, complaint, "open", opentime),
        )
        conn.commit()
        # conn.close()
    # get the list of complaints by the user from the complaints table.
    # the user is the current user
    # the complaints table has the following fields:
    # complaint_id, user_id, about, complaint, status, date, joined to user table on user_id
    # select u.email, c.about, c.complaint, c.status, c.opendate, c.closedate from complaints c inner join users u on u.user_id = c.user_id
    c.execute(
        """
    select u.email, cp.complaint_id, cp.about, cp.complaint, cp.status, cp.opendate, cp.closedate, cp.comments 
    from complaints cp inner join users u on u.user_id = cp.user_id
    where u.email = ?
    """,
        (current_user.id,),
    )
    complaints = c.fetchall()
    conn.close()
    return render_template("AddComplaint.html", complaints=complaints)


@app.route("/AddUsers", methods=["GET", "POST"])
@login_required
def AddUsers():
    # accesible only to if the role is admin
    if current_user.role != "admin":
        return abort(401)
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    if request.method == "POST":
        email = request.form["email"]
        SalC = request.form["SalC"]
        # check for empty fields
        if email == "" or SalC == "":
            return render_template(
                "undercon.html",
                msg="Please fill in all fields. Press back and try again!",
            )
        # insert the user into the users table, with role = user, active = 1
        c.execute(
            """
        insert into users (email, salC, role, active) values (?, ?, ?, ?)
        """,
            (email, SalC, "user", 1),
        )
        conn.commit()

    # get the list of users from the users table
    c.execute(
        """
    select * from users
    """
    )
    users = c.fetchall()
    conn.close()
    return render_template("AddUser.html", users=users)
    # return "AddUsers"


@app.route("/ViewComplaint", methods=["GET"])
@login_required
def ViewComplaint():
    # only allowed if the role is admin
    if current_user.role != "admin":
        return abort(401)
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    # get the list of complaints from the complaints table
    c.execute(
        """
    select u.email, cp.complaint_id, cp.about, cp.complaint, cp.status, cp.opendate, cp.closedate, cp.comments
    from complaints cp inner join users u on u.user_id = cp.user_id
    """
    )
    complaints = c.fetchall()
    conn.close()
    return render_template("ViewAll.html", complaints=complaints)


@app.route("/ResolveComplaint", methods=["GET", "POST"])
@login_required
def ResolveComplaint():
    # only allowed if the role is admin
    if current_user.role != "admin":
        return abort(401)
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    if request.method == "POST":
        complaint_id = request.form["complaint_id"]
        comments = request.form["comments"]
        # check for empty fields
        if complaint_id == "":
            return render_template(
                "undercon.html",
                msg="Please fill in all fields. Press back and try again!",
            )
        # update the complaint status to closed in the complaints table
        c.execute(
            """
        update complaints set status = ?, closedate = ?, comments = ? where complaint_id = ?
        """,
            (
                "closed",
                time.strftime("%b-%d-%Y %H:%M:%S", time.localtime()),
                comments,
                complaint_id,
            ),
        )

        conn.commit()
    # get the list of complaints from the complaints table
    c.execute(
        """
    select u.email, cp.complaint_id, cp.about, cp.complaint, cp.status, cp.opendate, cp.closedate, cp.comments
    from complaints cp inner join users u on u.user_id = cp.user_id
    where cp.status = 'open'
    """
    )
    complaints = c.fetchall()
    conn.close()
    return render_template("ResolveComplaint.html", complaints=complaints)


@app.route("/undercon")
@login_required
def undercon():
    return render_template(
        "undercon.html",
        msg="You should not see this page. Select an option from the left menu bar",
    )  # , current_user=current_user.id
    # )  #'Logged in as: ' + current_user.id


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


@login_manager.unauthorized_handler
def unauthorized_handler():
    abort(401)
    # return "Unauthorized"


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


def create_tables():
    """create a new database if the database doesn't already exist
    database name maint.db
    tables
    1. users. Columns: user_id(primary key, autoincrementing), email(text), salC(numeric), role(text), active(boolean)
    2. complaints. Columns: complaint_id(primary key, autoincrementing), user_id(foreign key), about(text),
        complaint(text), status(text), opendate(date), closedate(date)
    """
    conn = sqlite3.connect("maint.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        salC NUMERIC,
        role TEXT,
        active BOOLEAN
    )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS complaints (
        complaint_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        about TEXT,
        complaint TEXT,
        status TEXT,
        opendate DATE,
        closedate DATE,
        comments TEXT,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )"""
    )


if __name__ == "__main__":
    create_tables()
    app.run(
        debug=True, host="0.0.0.0"
    )  # drop the host parameter to make this local-only
    # # available across the network at the moment.
