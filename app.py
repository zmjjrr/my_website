from flask import *
import sqlite3
import os
import subprocess
import bcrypt

app=Flask(__name__)
app.secret_key = os.urandom(8)

class NonTemporaryDB:
    def __init__(self, db_file_path):
        self.db_file = db_file_path

    def execute(self, sql, parameters=()):
        try:
            with sqlite3.connect(self.db_file) as connection:
                connection.row_factory = sqlite3.Row
                cursor = connection.cursor()
                result = cursor.execute(sql, parameters)
                connection.commit()
                return result
        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
            return None
        
db = NonTemporaryDB('data.db')
db.execute("""CREATE TABLE IF NOT EXISTS posts ( 
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           username TEXT NOT NULL,
           content TEXT NOT NULL)""")

db.execute("""CREATE TABLE IF NOT EXISTS users (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           privilege TEXT NOT NULL,
           username TEXT NOT NULL, 
           password TEXT NOT NULL)""")

@app.route("/message_board", methods=["POST"])
def post():
    content = request.form.get("content", "")
    username = session.get('username')
    if username:
        db.execute("INSERT INTO posts (content,username) VALUES (?,?)", [content,username])
        return redirect(request.path)
    else:
        return '请先登录', 400

@app.route("/message_board", methods=["GET"])
def show_posts():
    posts = db.execute("SELECT * FROM posts").fetchall()
    privilege = session.get('privilege')
    username = session.get('username')
    return render_template('message_board.html', posts=posts, privilege=privilege, username=username)

@app.route("/message_board/delete", methods=["POST"])
def delete_posts():
    id = int(request.form.get('id'))
    username = session.get('username')
    privilege = session.get('privilege')
    if privilege == 'root':
        db.execute("DELETE FROM posts WHERE id = ?", [id])
    else:
        db.execute("DELETE FROM posts WHERE id = ? AND username = ?", [id,username])
    return redirect('/message_board')


@app.route('/')
def home():
    username = session.get('username')
    privilege = session.get('privilege')
    return render_template('home.html',username = username, privilege = privilege)

@app.route('/sbEncryptor')
def index():
    return render_template('sbEncryptor.html')

@app.route('/hello')
def hello():
    return render_template('hello.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('register-username')
        password = request.form.get('register-password')
        confirm_password = request.form.get('confirm-password')

        if password != confirm_password:
            return "两次输入的密码不一致", 400

        # 检查用户名是否已存在
        existing_user = db.execute("SELECT * FROM users WHERE username =?", [username]).fetchone()
        if existing_user:
            return "用户名已存在", 400

        # 插入新用户
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db.execute("INSERT INTO users (username, password, privilege) VALUES (?,?,'user')", [username, hashed])
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = db.execute("SELECT * FROM users WHERE username = ?", [username]).fetchone()
        if user:
            stored_password = user['password'].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['username'] = username
                session['privilege'] = user['privilege']
                return redirect('/')
        else:
            return "用户名或密码错误", 400
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/safe_command')
def safe_command():
    try:
        command = "echo 'hello hacker'"
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.stderr}"

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)