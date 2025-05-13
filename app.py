# app.py
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Message
from datetime import datetime, timezone, timedelta
from crypto_utils import aes_encrypt, aes_decrypt
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inisialisasi extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # jika belum login → redirect kesini

session_keys = {}  # menyimpan AES key untuk setiap user



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create DB tables on first run
with app.app_context():
    db.create_all()

# Route: Home (protected)
@app.route('/')
@login_required
def index():
    users = User.query.all()
    return render_template('index.html', user=current_user, users=users)
  
@app.route('/chat/<int:with_id>')
@login_required
def chat_with(with_id):
    other = User.query.get_or_404(with_id)
    return render_template('chat.html', other=other)


# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd   = request.form['password']
        if User.query.filter_by(username=uname).first():
            flash('Username sudah terpakai', 'danger')
            return redirect(url_for('register'))
        user = User(username=uname)
        user.set_password(pwd)
        db.session.add(user)
        db.session.commit()
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd   = request.form['password']
        user = User.query.filter_by(username=uname).first()
        if user and user.check_password(pwd):
            login_user(user)
            session_keys[user.id] = get_random_bytes(32)  # generate AES key
            return redirect(url_for('index'))
        flash('Username atau password salah', 'danger')
    return render_template('login.html')

# Route: Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout', 'info')
    return redirect(url_for('login'))

def utc_to_wib(utc_datetime):
    """Mengkonversi waktu UTC ke Waktu Indonesia Barat (WIB/UTC+7)"""
    if utc_datetime.tzinfo is None:
        # Jika datetime tidak memiliki info timezone, asumsikan UTC
        utc_datetime = utc_datetime.replace(tzinfo=timezone.utc)
    
    # WIB adalah UTC+7
    wib_timezone = timezone(timedelta(hours=7))
    wib_datetime = utc_datetime.astimezone(wib_timezone)
    return wib_datetime

# Route: Send Message
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    to_id = int(data['to_id'])
    content = data['content']
    
    # Gunakan kunci yang sama untuk kedua pengguna
    chat_key_name = f"chat_{min(current_user.id, to_id)}_{max(current_user.id, to_id)}"
    if chat_key_name not in session_keys:
        session_keys[chat_key_name] = get_random_bytes(32)
    aes_key = session_keys[chat_key_name]
    
    # Enkripsi dan simpan pesan seperti biasa
    ciphertext = aes_encrypt(content.encode(), aes_key).hex()
    msg = Message(sender_id=current_user.id,
                  receiver_id=to_id,
                  content=ciphertext)
    db.session.add(msg)
    db.session.commit()
    
    
    return jsonify({
      "id": msg.id,
      "ciphertext": ciphertext,
      "timestamp": msg.timestamp.isoformat()
    }), 201
    
    
    
    # Modifikasi fungsi get_messages di app.py
@app.route('/get_messages/<int:with_id>')
@login_required
def get_messages(with_id):
    # Buat kunci enkripsi yang SAMA untuk kedua pengguna
    chat_key_name = f"chat_{min(current_user.id, with_id)}_{max(current_user.id, with_id)}"
    
    # Gunakan kunci yang sudah ada atau buat kunci baru jika belum ada
    if chat_key_name not in session_keys:
        session_keys[chat_key_name] = get_random_bytes(32)
    
    aes_key = session_keys[chat_key_name]
    
    # Query pesan seperti biasa
    msgs = Message.query.filter(
      ((Message.sender_id == current_user.id) & (Message.receiver_id == with_id)) |
      ((Message.sender_id == with_id) & (Message.receiver_id == current_user.id))
      ).order_by(Message.timestamp).all()
    
    result = []
    for m in msgs:
        ct = m.content
        try:
            # Coba dekripsi dengan kunci chat bersama
            pt = aes_decrypt(bytes.fromhex(ct), aes_key).decode()
        except Exception as e:
            # Jika gagal, gunakan placeholder
            pt = "[Pesan terenkripsi]"
        
        result.append({
            "id": m.id,
            "from": m.sender_id,
            "to": m.receiver_id,
            "ciphertext": ct,
            "plaintext": pt,
            "timestamp": m.timestamp.isoformat()
        })
    
    return jsonify(result), 200

@app.route('/messages/<int:with_id>', methods=['GET'])
@login_required
def get_messages_alias(with_id):
    # Cukup panggil fungsi get_messages yang sudah ada:
    return get_messages(with_id)

    
if __name__ == '__main__':
    app.run(debug=True)



