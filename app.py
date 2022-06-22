from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flaskext.mysql import MySQL
import pymysql
from flask_login import login_required, user_logged_in
from wtforms import Form, StringField, IntegerField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "Thisisasecretkey"

mysql = MySQL()

# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'PASSWORD'
app.config['MYSQL_DATABASE_DB'] = 'flaskdb'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/')
def base():
    return render_template('home.html')


class MarksForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    marks = IntegerField('Marks')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        # Execute query
        cur.execute("INSERT INTO user(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))
        # Commit to DB
        conn.commit()
        # Close connection
        cur.close()
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        # Get user by username
        result = cur.execute("SELECT * FROM user WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    # Get articles
    # result = cur.execute("SELECT * FROM articles")
    # Show articles only from the user logged in
    result = cur.execute("SELECT * FROM marks WHERE user = %s", [session['username']])

    articles = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Marks Found'
        return render_template('dashboard.html', msg=msg)
    # Close connection
    cur.close()


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/add_marks', methods=['GET', 'POST'])
@is_logged_in
def add_marks():
    form = MarksForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        marks = form.marks.data

        # Create Cursor
        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        # Execute
        cur.execute("INSERT INTO marks(name, marks, user) VALUES(%s, %s, %s)", (name, marks, session['username']))
        # Commit to DB
        conn.commit()
        # Close connection
        cur.close()
        flash('Marks Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_marks.html', form=form)


@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_marks(id):
    # Create cursor
    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    # Execute
    cur.execute("DELETE FROM marks WHERE id = %s", [id])
    # Commit to DB
    conn.commit()
    # Close connection
    cur.close()
    flash('Marks Deleted', 'success')
    return redirect(url_for('dashboard'))


@app.route('/edit_marks/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_marks(id):
    # Create cursor
    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    # Get article by id
    result = cur.execute("SELECT * FROM marks WHERE id = %s", [id])
    article = cur.fetchone()
    cur.close()
    # Get form
    form = MarksForm(request.form)
    # Populate article form fields
    form.name.data = article['name']
    form.marks.data = article['marks']

    if request.method == 'POST' and form.validate():
        name = request.form['name']
        marks = request.form['marks']
        # Create Cursor
        cur = conn.cursor(pymysql.cursors.DictCursor)
        app.logger.info(name)
        # Execute
        cur.execute("UPDATE marks SET name=%s, marks=%s WHERE id=%s", (name, marks, id))
        # Commit to DB
        conn.commit()
        # Close connection
        cur.close()
        flash('Marks Updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_marks.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)