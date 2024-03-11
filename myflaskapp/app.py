# Importing necessary modules
import awsgi
from flask import Flask, render_template, request, jsonify,redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, validators
from flask_login import LoginManager, logout_user
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound


# Initializing Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:swathi@localhost/rest api'  
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
 
# It will Define the properties for Flask-Login
    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

# Custom validation: check if there are no whitespaces in the password    
def validate_no_whitespace(form, field):
    print("Validating no whitespace...")
    if ' ' in field.data:
        raise validators.ValidationError('Password should not contain white spaces')
    
# Registration Form using FlaskForm    
class RegistrationForm(FlaskForm):
    # Define registration form fields with validation rules
    first_name = StringField('First Name', [
        validators.InputRequired(),
        validators.Length(min=2, max=50, message='First name must be between 2 and 50 characters'),
        validators.Regexp(regex=r'^[a-zA-Z]*$', message='First name must contain only letters')
    ])
    last_name = StringField('Last Name', [
        validators.InputRequired(),
        validators.Length(min=2, max=50, message='Last name must be between 2 and 50 characters'),
        validators.Regexp(regex=r'^[a-zA-Z]*$', message='Last name must contain only letters'),
        
    ])
    email = StringField('Email', [validators.InputRequired(), validators.Email()])
    password = PasswordField('Password', [
        validators.InputRequired(),
        validators.Length(min=8, max=20, message='Password must be between 8 and 20 characters long'),
        validators.Regexp(regex=r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%&*()-+=^]).*$', message='Invalid password format'),
        validators.Regexp(regex=r'.*\d.*', message='Password must contain at least one digit'),
        validators.Regexp(regex=r'.*[a-z].*', message='Password must contain at least one lowercase letter'),
        validators.Regexp(regex=r'.*[A-Z].*', message='Password must contain at least one uppercase letter'),
        validators.Regexp(regex=r'.*[!@#$%&*()-+=^].*', message='Password must contain at least one special character (!@#$%&*()-+=^)'),
        validate_no_whitespace
    ])
    confirm_password = PasswordField('Confirm Password', [
        validators.EqualTo('password', message='Passwords must match'),
        validators.InputRequired()
    ])

###########login form##############
class LoginForm(FlaskForm):
    email = StringField('Email', [validators.InputRequired(), validators.Email()])
    password = PasswordField('Password', [validators.InputRequired()])

# Routes for HTML pages

"""@app.route('/')
def index():
    form = RegistrationForm()
    return render_template('index.html', form=form)"""

# Flask route for the index page
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    
    user=None

    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data

        # Dummy authentication (replace with actual authentication logic)
        user = find_user_by_email(email)

        if user and user.password == password:
            flash('Login successful!', 'success')
            return redirect(url_for('account', user_id=user.id))

        # Check if the user is not found
        if user is None:
            flash('User not found. Please check your email or register.', 'error')
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('index.html', form=form, user=user)

# Function to find a user by using email
def find_user_by_email(email):
    try:
        return User.query.filter_by(email=email).one()
    except NoResultFound:
        return None            

# Flask route for the account page
@app.route('/account/<int:user_id>')
def account(user_id):
    user = User.query.get(user_id)
    if user:
        return render_template('account.html', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('index'))
    
# Flask route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data

        # Check if the email address already exists in the database
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'error')
            return redirect(url_for('register'))

        try:
            # Create a new user and add to the database
            new_user = User(first_name=first_name, last_name=last_name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()

            # Flash a success message
            flash('User registered successfully!', 'success')
            print("Success message flashed.")

            # Redirect to the account page for the newly registered user
            return redirect(url_for('account', user_id=new_user.id))

        except IntegrityError:
            db.session.rollback()
            flash('Email address is already registered. Please use a different email.', 'error')
            return redirect(url_for('register'))
    
    print("Errors:", form.errors)  # Add this line to print form validation errors
    return render_template('register1.html', form=form)

# Flask route for getting all users 
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'first_name': user.first_name, 'last_name': user.last_name, 'email': user.email} for user in users]
    return jsonify(user_list)

# Flask route for creating a new user 
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    new_user = User(first_name=data.get('first_name'), last_name=data.get('last_name'), email=data.get('email'), password=data.get('password'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201  # 201 Created status

# Flask route for getting a specific user 
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'id': user.id, 'first_name': user.first_name, 'last_name': user.last_name, 'email': user.email})
    return jsonify({'message': 'User not found'}), 404

# Flask route for updating a user
@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    user = User.query.get(user_id)

    if user:
        if request.method == 'POST':
            user.first_name = request.form.get('first_name', user.first_name)
            user.last_name = request.form.get('last_name', user.last_name)
            user.email = request.form.get('email', user.email)
            user.password = request.form.get('password', user.password)
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('account', user_id=user.id))

        return render_template('update_user.html', user=user)

    flash('User not found', 'error')
    return redirect(url_for('index'))

# Flask route for deleting a user
@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        print("User deleted successfully!")
        return redirect(url_for('index'))  # Redirect to the index1 page after deleting

    print("User not found!")
    return jsonify({'message': 'User not found'}), 404

# Flask route for logging out
@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))


def lambda_handler(event, context):
    try:
        print("Event:", event)  # Log the entire event for debugging
        return awsgi.response(app, event, context, base64_content_types={"image/png"})
    except Exception as e:
        print("Error:", str(e))  # Log the error for debugging
        return {'statusCode': 500, 'body': f'Error: {str(e)}'}

    
if __name__ == '__main__':
    # Create database tables before running the application
    with app.app_context():
        db.create_all()
    app.run(debug=True)
