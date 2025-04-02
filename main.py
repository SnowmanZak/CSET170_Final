from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, text
import bcrypt


app = Flask(__name__)

conn_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(conn_str, echo = True)
conn = engine.connect()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        ssn = request.form.get('ssn')
        address = request.form.get('address')
        phone = request.form.get('phone_num')
        password = request.form.get('password')
        
        hashed_password = hash_password(password)

        try:
            with engine.begin() as conn:
                check_existing = conn.execute(
                    text('SELECT * FROM users WHERE username = :username'),
                    {'username': username}
                ).fetchone()  
                
                if check_existing:  
                    return render_template('create_acc.html', error="Username is already in use.")
                else:
                    log_other_users_out(conn)
                    

                    conn.execute(
                        text('''
                            INSERT INTO users (username, first_name, last_name, ssn, address, phone, password, logged_in)
                            VALUES (:username, :first_name, :last_name, :ssn, :address, :phone, :password, :logged_in)
                        '''),
                        {'username': username, 'first_name': first_name, 'last_name': last_name, 'ssn': ssn, 'address': address, 'phone': phone, 'password': hashed_password, 'logged_in': True}
                    )
                    return redirect(url_for('home'))  

        except Exception as e:
            return render_template('create_acc.html', error=f'An error occurred: {str(e)}')

    return render_template('create_acc.html')


@app.route('/login', methods=['GET'])
def gologin():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    with engine.begin() as conn:
        username = request.form.get('username')
        password = request.form.get('password')

        user = conn.execute(
            text('SELECT * FROM users WHERE username = :username'),
            {'username': username}
        ).mappings().first()

        if user and check_password(password, user['password']):
            log_other_users_out(conn)

            conn.execute(
                text('UPDATE users SET logged_in = 1 WHERE user_id = :user_id'),
                {'user_id': user['user_id']}
            )

            logged_in_user = get_logged_in_user()

            return redirect(url_for('home', user=logged_in_user))
        else:
            return render_template('login.html', error="Invalid credentials.")





# FUNCTIONS BELOW 
# Hashing password
def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Function to check password
def check_password(entered_password, stored_hash):
    return bcrypt.checkpw(entered_password.encode("utf-8"), stored_hash.encode("utf-8"))



# Logging out any user already logged in
def log_other_users_out(connect):
    check_logged = connect.execute( # query to see if anyone is logged in
        text('SELECT * FROM users WHERE logged_in = 1') # 1 = True, 0 = False
    ).fetchone()

    if check_logged: # logs out anyone logged in already
        connect.execute(
            text('UPDATE users SET logged_in = 0 WHERE logged_in = 1')
        )

# creates admin a first account if there is not one already in the database, so it'll be the first account every time
def create_admin_account():
    with engine.begin() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")).fetchone()
        
        if result[0] == 0:  
            admin_password = "admin123"  
            hashed_password = hash_password(admin_password)
            conn.execute(text("""
                INSERT INTO users (username, first_name, last_name, ssn, address, phone, password, is_admin, is_approved, logged_in)
                VALUES (:username, :first_name, :last_name, :ssn, :address, :phone, :password, TRUE, TRUE, TRUE)
            """), {
                "username": "admin",
                "first_name": "Admin",
                "last_name": "User",
                "ssn": "000-00-0000",
                "address": "123 Admin St",
                "phone": "123-456-7890",
                "password": hashed_password
            })


def get_logged_in_user():
    with engine.connect() as conn:
        user = conn.execute(text("SELECT * FROM users WHERE logged_in = 1 LIMIT 1")).mappings().first()
    return user if user else None





if __name__ == '__main__': 

    create_admin_account()

    app.run(debug = True)