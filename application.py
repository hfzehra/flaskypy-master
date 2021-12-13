import os

from time import localtime, strftime, time
from flask import Flask, render_template, url_for, redirect, flash, request, flash
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_socketio import SocketIO, send, emit, join_room, leave_room

from wtform_fields import *
from models import User, db


#confirm app
app= Flask(__name__)
socketio = SocketIO(app, menage_session=False)
app.secret_key = os.environ.get('SECRET')


# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

db.init_app(app)


#Initialize Flask-SocketIO
#menage_session=False eklendi

ROOMS = ["lounge", "news", "games","coding"]

# Configure flask login

login = LoginManager(app)
login.init_app(app)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))



@app.route("/", methods=['GET', 'POST'])
def index():

    reg_form = RegistrationForm()
    # update database if validation success
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data

        # hash password
        hashed_password = pbkdf2_sha256.hash(password)


        # add user to db
        user =User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Registered succesfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template("index.html",form=reg_form)

@app.route("/login", methods=['GET','POST'])
def login():

    login_form = LoginForm()

    #Allow login  if validation success
    if login_form.validate_on_submit():
        user_object = User.query.filter_by(username=login_form.username.data).first()
        login_user(user_object)
        return redirect(url_for('chat'))

        return "Not logged in with :("

    return render_template("login.html",form =login_form)

@app.route("/chat",methods=['GET','POST'])
def chat():
    #if not current_user.is_authenticated:
        #flash('Please login.', 'danger')
        #return redirect(url_for('login'))

    return render_template('chat.html', username=current_user.username,rooms=ROOMS)


@app.route("/logout", methods=['GET'])
def logout():
    logout_user()
    flash('You have logged out successfully', 'success')
    return redirect(url_for('login'))


"""@socketio.on('message')
def message(data):

    print(f"\n\n{data}\n\n")
    send({'msg': data['msg'], 'username': data['username'], 'time_stamp': strftime('%b-%d-%I:%M%p', localtime())}, room=data['room'])"""
@socketio.on('incoming-msg')
def on_message(data):
    """Broadcast messages"""

    msg = data["msg"]
    username = data["username"]
    room = data["room"]
    # Set timestamp
    time_stamp = strftime('%b-%d %I:%M%p', localtime())
    send({"username": username, "msg": msg, "time_stamp": time_stamp}, room=room)


"""@socketio.on('join')
def join(data):

    join_room(data['room'])
    send({'msg': data['username'] + "has joined the " + data['room'] + "room."}, room=data['room'])"""
@socketio.on('join')
def on_join(data):
    """User joins a room"""

    username = data["username"]
    room = data["room"]
    join_room(room)

    # Broadcast that new user has joined
    send({"msg": username + " has joined the " + room + " room."}, room=room)



"""@socketio.on('leave')
def leave(data):
    leave_room(data['room'])
    send({'msg': data['username'] + " has left the " + data['room'] + "room."}, room=data['room'])"""
@socketio.on('leave')
def on_leave(data):
    """User leaves a room"""

    username = data['username']
    room = data['room']
    leave_room(room)
    send({"msg": username + " has left the room"}, room=room)


if __name__ == "__main__":
    socketio.run(app, debug=True)