import os
from flask import Flask, redirect, url_for
from flask_admin import Admin, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user, LoginManager

from app.extension import db
from app.models import User, ClientUser, ThreatIP, Indicator

# ------------ Custom Admin Views (Admin Login Only) ------------ #
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        # Admin login check
        if not current_user.is_authenticated or not isinstance(current_user, User):
            return redirect(url_for('main.admin_login'))  # Show login.html
        return super().index()


class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and isinstance(current_user, User)

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.admin_login'))


# ------------ Flask-Admin Setup ------------ #
admin = Admin(
    name='Threat Intel Admin',
    template_mode='bootstrap4',
    index_view=MyAdminIndexView()
)

# ------------ Flask-Login Setup ------------ #
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    # Try to load admin user
    user = User.query.get(int(user_id))
    if user:
        return user
    # Fallback to client user
    return ClientUser.query.get(int(user_id))


# ------------ App Factory ------------ #
def create_app():
    app = Flask(__name__)

    # Config
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kajal%40123@localhost:5432/Threat_data'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.home'  # Redirect clients to client login

    # Register admin views
    admin.init_app(app)
    admin.add_view(SecureModelView(ThreatIP, db.session))
    admin.add_view(SecureModelView(Indicator, db.session))

    # Register main app blueprint
    from app.routes import main
    app.register_blueprint(main)

    return app
