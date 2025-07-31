from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import ClientUser, User  # Admin and client users
from app.database import get_db_connection
from app import db

main = Blueprint('main', __name__)

# ------------------ Home Page (Client Login Page) ------------------ #
@main.route('/')
def home():
    return render_template('home.html')


# ------------------ Client Login Handler (Auto-register if new) ------------------ #
@main.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = ClientUser.query.filter_by(username=username).first()

    if user:
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.landing'))
        else:
            flash('Invalid password.', 'danger')
    else:
        # Auto-register new client user
        hashed_pw = generate_password_hash(password)
        new_user = ClientUser(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('main.landing'))

    return redirect(url_for('main.home'))


# ------------------ Landing Page After Login ------------------ #
@main.route('/landing')
@login_required
def landing():
    return render_template('landing.html', user=current_user)


# ------------------ Dashboard Page ------------------ #
@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


# ------------------ Logout ------------------ #
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))


# ------------------ Admin Login ------------------ #
@main.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/admin')
        else:
            flash('Invalid admin credentials.', 'danger')

    return render_template('login.html')


# ------------------ API: Summary Stats ------------------ #
@main.route('/api/summary/stats')
def summary_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM threat_ips")
    total_ips = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT country) FROM threat_ips WHERE country IS NOT NULL AND country <> ''")
    total_countries = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT isp) FROM threat_ips WHERE isp IS NOT NULL AND isp <> ''")
    total_isps = cur.fetchone()[0]

    cur.execute("SELECT MAX(last_seen) FROM threat_ips")
    last_seen = cur.fetchone()[0]

    cur.close()
    conn.close()

    return jsonify({
        'total_ips': total_ips,
        'total_countries': total_countries,
        'total_isps': total_isps,
        'last_seen': last_seen.strftime('%Y-%m-%d %H:%M:%S') if last_seen else None
    })


# ------------------ API: Top Countries ------------------ #
@main.route('/api/summary/countries')
def summary_countries():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT country, COUNT(*) 
        FROM threat_ips 
        WHERE country IS NOT NULL AND country <> ''
        GROUP BY country 
        ORDER BY COUNT(*) DESC 
        LIMIT 10
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)


# ------------------ API: Abuse Categories ------------------ #
@main.route('/api/summary/abuse_categories')
def summary_abuse_categories():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT abuse_categories, COUNT(*) 
        FROM threat_ips 
        WHERE abuse_categories IS NOT NULL AND abuse_categories <> ''
        GROUP BY abuse_categories 
        ORDER BY COUNT(*) DESC 
        LIMIT 10
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)


# ------------------ API: Daily Threat Trend ------------------ #
@main.route('/api/summary/daily_trend')
def summary_daily_trend():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT TO_CHAR(last_seen, 'YYYY-MM-DD') AS date, COUNT(*) 
        FROM threat_ips 
        WHERE last_seen IS NOT NULL
        GROUP BY TO_CHAR(last_seen, 'YYYY-MM-DD') 
        ORDER BY date
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)


# ------------------ API: Threat Map Data ------------------ #
@main.route('/api/summary/map')
def summary_map():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT ip_address, country, city 
        FROM threat_ips 
        WHERE country IS NOT NULL AND city IS NOT NULL AND country <> '' AND city <> ''
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)
