from flask import Flask, request, render_template , redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from wtforms.fields import PasswordField
from datetime import datetime
from flask_admin import Admin, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView
import secrets

# Initialize Flask app and configure database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# User model for storing user details
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(120), nullable=False, default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
# RecentActivity model for logging user activities
class RecentActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    activity = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(120), nullable=False, default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def __repr__(self):
        return f'<Activity {self.username} - {self.activity}>'
    
# Checks if a user already exists in the database
def check_if_user_exists(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return True
    return False

# Checks if the provided username and password are valid
def check_creds(username, password):
    user = User.query.filter_by(username=username).first()
    if user and Bcrypt().check_password_hash(user.password, password):
        return True
    return False

# Creates a default admin user if one doesn't already exist
def create_default_admin():
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password= Bcrypt().generate_password_hash('admin').decode('utf-8'), 
            is_admin=True,
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        db.session.add(admin_user)
        db.session.commit()

# Secure model view for managing users in the admin panel
class SecureModelView(ModelView):
    column_exclude_list = ['password']
    form_excluded_columns = ['password']

    form_extra_fields = {
        'new_password': PasswordField('New Password')
    }

    def on_model_change(self, form, model, is_created):
        # If a new password is entered, hash and set it
        if form.new_password.data:
            model.password = Bcrypt().generate_password_hash(form.new_password.data).decode('utf-8')
            # Log the password change activity
            activity = RecentActivity(
                username=model.username,
                activity='Password changed',
                date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
            db.session.add(activity)
            db.session.commit()

    def on_model_delete(self, model):
        # Log the user deletion activity
        activity = RecentActivity(
            username=model.username,
            activity='User deleted',
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        db.session.add(activity)
        db.session.commit()

    # Checks if the current user has admin access
    def is_accessible(self):
        return session.get('is_admin') == True

    # Redirects non-admin users to the index page
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))
    
# Custom admin index view
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        total_users = User.query.count()
        total_admins = User.query.filter_by(is_admin=True).count()
        return self.render('admin/index.html', total_users=total_users, total_admins=total_admins)

    # Checks if the current user has admin access
    def is_accessible(self):
        return session.get('is_admin') == True

    # Redirects non-admin users to the index page
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

# Model view for displaying recent activities in the admin panel
class RecentActivityView(ModelView):
    column_list = ['username', 'activity', 'date']
    can_create = False
    can_edit = False
    can_delete = False

    # Checks if the current user has admin access
    def is_accessible(self):
        return session.get('is_admin') == True

    # Redirects non-admin users to the index page
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

# Route for the home page, handles login
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('username')
        pwd = request.form.get('password')
        dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if (name and pwd) != None and check_creds(name, pwd):
            session['username'] = name
            session['password'] = pwd
            session['is_admin'] = User.query.filter_by(username=name).first().is_admin
            session['date'] = dt
            activity= RecentActivity(username=name, activity='Login', date=dt)
            db.session.add(activity)
            db.session.commit()
            return "Login successful!"
        
        else:
            return "User does not exist or invalid input."
    else:
        return render_template('index.html')
    
# Route for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('username')
        pwd = request.form.get('password')
        hashed_pwd = Bcrypt().generate_password_hash(pwd).decode('utf-8')
        dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if (name and pwd) != None and not check_if_user_exists(name): 
            new_user = User(username=name, password=hashed_pwd, date=dt)
            activity = RecentActivity(username=name, activity='Signup', date=dt)
            db.session.add(activity)
            db.session.add(new_user)
            db.session.commit()
            return f"User {name} added successfully!"
        else:
            return "Sorry, user already exists or invalid input."
    else:
        return render_template('signup.html')
    
# Initializes the admin panel
def initAdmin():
    admin = Admin(app, name='My Admin', index_view=MyAdminIndexView())
    admin.add_view(SecureModelView(User, db.session))
    admin.add_view(RecentActivityView(RecentActivity, db.session))

# Route for user logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Injects the current year into templates
@app.context_processor
def inject_year():
    from datetime import datetime
    return {'current_year': datetime.now().year}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
        create_default_admin()  # Create a default admin user
    initAdmin()  # Initialize the admin panel
    app.run(debug=True)