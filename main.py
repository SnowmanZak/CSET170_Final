from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, text
import bcrypt
import random

app = Flask(__name__)

conn_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(conn_str, echo = True)
conn = engine.connect()

@app.route('/')
def home():
    user = get_logged_in_user()
    is_admin = user['is_admin'] if user else 0
    logged_in = bool(user)

    return render_template('index.html', is_admin=is_admin, logged_in=logged_in)

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

            return redirect(url_for('home', user=logged_in_user, logged_in=True))
        else:
            return render_template('login.html', error="Invalid credentials.")


@app.route('/accounts')
def accounts():
    user = get_logged_in_user()

    if not user or user['is_admin'] == 0:
        return redirect(url_for('home'))  

    with engine.connect() as conn:
        accounts = conn.execute(text("SELECT user_id, username, first_name, last_name, ssn, address, phone, is_approved FROM users")).mappings().all()

    return render_template('accounts.html', accounts=accounts, is_admin=user['is_admin'])



@app.route('/approve', methods=['GET', 'POST'])  
def approve():
    user = get_logged_in_user()

    if not user or user['is_admin'] == 0:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        with engine.connect() as conn:
            already_approved = conn.execute(
                text("SELECT is_approved FROM users WHERE user_id = :uid"),{"uid": user_id}).scalar()

            if already_approved == 0:
                conn.execute(
                    text("UPDATE users SET is_approved = 1 WHERE user_id = :uid"),{"uid": user_id})
                conn.commit()

                assign_bank_account_number(user_id)

    with engine.connect() as conn:
        accounts = conn.execute(
            text("SELECT user_id, username, first_name, last_name, ssn, address, phone FROM users WHERE is_approved = 0")).mappings().all()

    return render_template('approve.html', accounts=accounts, is_admin=user['is_admin'])



@app.route('/log-out', methods=['GET', 'POST'])
def log_out():
    user = get_logged_in_user()
    
    with engine.begin() as conn:
        conn.execute(
            text('UPDATE users SET logged_in = 0 WHERE user_id = :uid'),
            {'uid': user['user_id']}
        )
    
    return render_template('index.html', logged_in = False)
    

@app.route('/your_account', methods = ['GET', 'POST'])
def your_account():
    user = get_logged_in_user()

    if not user:
        return redirect(url_for('index'))
    
    with engine.begin() as conn:
        result = conn.execute(text('SELECT users.user_id, users.username, users.first_name, users.last_name, users.address, users.phone, ''bank_accounts.account_number, bank_accounts.balance '
                 'FROM users ''JOIN bank_accounts ON users.user_id = bank_accounts.user_id ''WHERE users.logged_in = 1 AND users.user_id = :user_id'),{'user_id': user['user_id']})
        account_details = result.mappings().first()

    if not account_details:
        return render_template('your_account.html', user=user, account_details=None)
    return render_template('your_account.html', user=user, account_details=account_details)




@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('home'))

    if request.method == 'POST':
        card_number = request.form.get('card_number')
        exp_date = request.form.get('exp_date')
        ccv = request.form.get('ccv')
        money_added = request.form.get('money_added')

        # Basic validation
        if len(card_number) < 15:
            return render_template('transaction.html', error='Invalid card number input')
        elif len(exp_date) < 3:
            return render_template('transaction.html', error='Invalid Expiration Date input. Ensure you use the proper MM/YY format')
        elif len(ccv) < 3:
            return render_template('transaction.html', error='Invalid CCV input')
        elif not money_added or not money_added.replace('.', '', 1).isdigit():
            return render_template('transaction.html', error='Amount must be a valid number')

        money_added = float(money_added)

        with engine.begin() as conn:
            # Insert into card_transactions
            conn.execute(
                text("""
                    INSERT INTO card_transactions (user_id, card_number, exp_date, cvv, amount)
                    VALUES (:uid, :card_number, :exp_date, :cvv, :amount)
                """),
                {
                    'uid': user['user_id'],
                    'card_number': card_number,
                    'exp_date': exp_date,
                    'cvv': ccv,
                    'amount': money_added
                }
            )

            # Update balance in bank_accounts
            conn.execute(
                text("""
                    UPDATE bank_accounts
                    SET balance = balance + :amount
                    WHERE user_id = :uid
                """),
                {
                    'amount': money_added,
                    'uid': user['user_id']
                }
            )

        return render_template('transaction.html', success='Transaction completed and balance updated!')

    return render_template('transaction.html')



@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    user = get_logged_in_user()

    if not user:
        return redirect(url_for('home'))

    if request.method == 'POST':
        receiver_account_number = request.form.get('receiver_account')
        amount = request.form.get('amount')
        description = request.form.get('description', '')

        if not receiver_account_number or not amount:
            return render_template('transfer.html', error='All fields are required.')

        try:
            amount = float(amount)
        except ValueError:
            return render_template('transfer.html', error='Amount must be a valid number.')

        with engine.begin() as conn:
            # Get sender's bank account
            sender = conn.execute(
                text("SELECT id, balance FROM bank_accounts WHERE user_id = :uid"),
                {"uid": user['user_id']}
            ).mappings().first()

            if not sender:
                return render_template('transfer.html', error='Your account was not found.')

            if sender['balance'] < amount:
                return render_template('transfer.html', error='Insufficient balance.')

            # Get receiver's bank account
            receiver = conn.execute(
                text("SELECT id FROM bank_accounts WHERE account_number = :acct"),
                {"acct": receiver_account_number}
            ).mappings().first()

            if not receiver:
                return render_template('transfer.html', error='Receiver account number not found.')

            # Update balances
            conn.execute(
                text("UPDATE bank_accounts SET balance = balance - :amt WHERE id = :sid"),
                {"amt": amount, "sid": sender['id']}
            )
            conn.execute(
                text("UPDATE bank_accounts SET balance = balance + :amt WHERE id = :rid"),
                {"amt": amount, "rid": receiver['id']}
            )

            # Log the transaction
            conn.execute(
                text("""
                    INSERT INTO transactions (sender_id, receiver_id, amount, transaction_type, description)
                    VALUES (:sid, :rid, :amt, 'debit', :desc),
                           (:rid, :sid, :amt, 'credit', :desc)
                """),
                {
                    "sid": sender['id'],
                    "rid": receiver['id'],
                    "amt": amount,
                    "desc": description
                }
            )

        return render_template('transfer.html', success='Transfer successful!')

    return render_template('transfer.html')


    




        

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

#gets logged in user
def get_logged_in_user():
    with engine.connect() as conn:
        user = conn.execute(text("SELECT * FROM users WHERE logged_in = 1 LIMIT 1")).mappings().first()
    return user if user else None

#generates random bank account number
def generate_account_number():
    return str(random.randint(1000000000, 9999999999))

#assigns account number to account
def assign_bank_account_number(user_id):
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT 1 FROM bank_accounts WHERE user_id = :uid"),{"uid": user_id}).first()

        if existing:
            return 

        account_number = generate_account_number()
        while conn.execute(
            text("SELECT 1 FROM bank_accounts WHERE account_number = :acct"),{"acct": account_number}).first():
            account_number = generate_account_number()
        conn.execute(text("""INSERT INTO bank_accounts (user_id, account_number) VALUES (:uid, :acct)"""),{"uid": user_id, "acct": account_number})
        conn.commit()

def log_out_on_start():
    with engine.connect() as conn:
        conn.execute(text('UPDATE users set logged_in = 0'))

if __name__ == '__main__': 

    create_admin_account()
    log_out_on_start()
    app.run(debug = True)