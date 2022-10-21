from flask import Flask, render_template, request, url_for, flash, redirect, session
from flask_login import LoginManager, login_required, logout_user
import sqlite3
from werkzeug.exceptions import abort
import init_db as db
from dotenv import load_dotenv
load_dotenv()
import os

# Connects to the db
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Manages the login sessions for the user
login_manager = LoginManager()
login_manager.init_app(app)


# route for the landing page
@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    #changes the name key value in the session dictionary to match the current users name
    return render_template('index.html', posts=posts)

#user profile function
@app.route('/profile', methods=('GET', 'POST'))
def profile():
    conn = get_db_connection()
    #takes the posts from the database made by the user whos profile youre on and returns them
    posts = conn.execute('SELECT * FROM posts WHERE user = ?',
            (session['name'],)).fetchall()
    conn.close()
    return render_template('profile.html', posts=posts)

#function that goes to post at selected ID
def get_post(post_id):
    #connects function to database
    conn = get_db_connection()
    #selects from posts in db and grabs the one that matches the post ID you want
    post = conn.execute('SELECT * FROM posts WHERE id = ?',
                        (post_id,)).fetchone()
    conn.close()
    #if there is no post with that ID returns 404 error page
    if post is None:
        abort(404)
    return post

#function that outputs the posts for users on the post page
@app.route('/<int:post_id>')
def post(post_id):
    post = get_post(post_id)
    return render_template('post.html', post=post)

#makes the page with the post input form
@app.route('/create', methods=('GET', 'POST'))
def create():
    #checks if there is an authenticated user logged in before allowing them to create posts
    if User.is_authenticated == True:
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']

            #there must be a title in each post before creating
            if not title:
                flash('Title is required!')
            else:
                conn = get_db_connection()
                conn.execute('INSERT INTO posts (title, content, user) VALUES (?, ?, ?)',
                            (title, content, session['name'],))
                conn.commit()
                conn.close()
                return redirect(url_for('index'))
    else:
        flash('You need to be logged in!')
        return redirect(url_for('index'))

    return render_template('create.html')

#goes to specified post to edit it
@app.route('/<int:id>/edit', methods=('GET', 'POST'))
def edit(id):
    #saves the id of the post in a string var
    post = get_post(id)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Title is required!')
        else:
            conn = get_db_connection()
            #updates the changes in the post
            conn.execute('UPDATE posts SET title = ?, content = ?'
                        ' WHERE id = ?',
                        (title, content, id))
            conn.commit()
            conn.close()
            return redirect(url_for('profile'))

    return render_template('edit.html', post=post)

#goes to specified post to delete it
@app.route('/<int:id>/delete', methods=('POST',))
def delete(id):
    post = get_post(id)
    conn = get_db_connection()
    #removes post at given ID from the database 
    conn.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    #shows user that the post was deleted
    flash('"{}" was successfully deleted!'.format(post['title']))
    return redirect(url_for('index'))

#user registration function 
@app.route('/register', methods=('GET', 'POST'))
def register():
    #checks if database recieved post request(submitted form)
    if request.method=='POST':
        #takes the users input for username,password
        username = request.form['username']
        password = request.form['password']
        Display_name = request.form['Display-name']

        conn = get_db_connection()
        user_login = conn.execute("SELECT username FROM users where username = ?",
                (username))
        user_login = user_login.fetchall()

        #checks if there is a user with that username
        if len(user_login) == 0:
            #inserts the username, and password into the database
            conn.execute("INSERT INTO users (username, pass, Display_name) VALUES (?, ?, ?)",
                    (username, password, Display_name))
            conn.commit()
            conn.close()
            flash(f'You have successfully registered as {Display_name}')
            return redirect(url_for('index'))
        else:
            flash('That username is already taken.')

    return render_template('register.html')

#user login function
@login_manager.user_loader
@app.route('/login', methods=('GET', 'POST'))
def login():
    #checks to see if the user is authenticated meaning they are logged in
    if request.method=='GET' and User.is_authenticated == True:
        flash(f'You are already logged in as {session["name"]}')
        return redirect(url_for('index'))
    else:
        if request.method=='POST':
            username = request.form['username']
            password = request.form['password']

            conn = get_db_connection()
            #selects username, and password from database that matches the login info
            user_login = conn.execute("SELECT username, pass FROM users where username = ? AND pass = ?",
                    (username, password))
            #grabs the user info that was selected
            user_login = user_login.fetchall()
            #checks if the info is correct(if there is a length of 1 that means the user info is correct)
            if len(user_login) == 1:
                id = conn.execute("SELECT id FROM users where username = ? and pass = ?",
                        (username, password))
                id = id.fetchone()

                Display_name = conn.execute("SELECT Display_name FROM users where username = ? and pass = ?",
                        (username, password))
                Display_name = Display_name.fetchone()

                #Changes values in User class
                User.name = Display_name
                User.id = id
                User.is_authenticated = True
                #changes the name key value in the session dictionary to match the current users name
                session["name"] = User.name
                flash(f'You have successfully logged in! {User.name}')
                conn.close()
                return redirect(url_for('index'))
            else:
                flash('The username or password are incorrect.')
                return redirect(url_for('login'))

    return render_template('login.html')

#user logout function
@app.route('/logout', methods=('GET', 'POST'))
def logout():
    #checks to see if user is active so they can log out
    if request.method=='GET'and User.is_authenticated == True:
        #removes the current user from the session using the name key
        session.pop("name")
        User.is_authenticated = False
        flash(f'You have successfully logged out {User.name}!')
        return redirect(url_for('index'))
    elif request.method=='GET' and User.is_authenticated == False:
        flash('You cannot log out without being logged in.')

    return redirect(url_for('index'))


class User():
    def __init__(self, name, id):
        self.name = name
        self.id = id

    def is_active(self):
        return self.active

    def is_authenticated(self):
        return False
