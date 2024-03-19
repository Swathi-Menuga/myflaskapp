import pytest
import warnings
from app import app, db, User
from sqlalchemy.orm import Session

# Fixture to set up the Flask application context
@pytest.fixture
def app_context():
    with app.app_context():
        yield

# Fixture to set up a test client
@pytest.fixture
def client(app_context):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:swathi@localhost/rest api'  # Use in-memory SQLite database for testing
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # Create all tables in the test database
            # Add sample user data to the test database only if it doesn't exist
            existing_user = User.query.filter_by(email='sunny@gmail.com').first()
            if not existing_user:
                sample_user = User(first_name='menugollu', last_name='sunny', email='sunny@gmail.com', password='Sunny@123')
                db.session.add(sample_user)
                db.session.commit()
        yield client

# Test registration form validation
def test_registration_form_validation():
    with app.test_request_context():
        from app import RegistrationForm
        form = RegistrationForm(
            first_name='menugollu',
            last_name='sunny',
            email='sunny@gmail.com',
            password='Sunny@123',
            confirm_password='Sunny@123'
        )
        assert not form.validate()

        # Test invalid email
        form.email.data = 'invalid_email'
        assert not form.validate()

        # Test password mismatch
        form.email.data = 'sunny@gmail.com'
        form.confirm_password.data = 'Sunny@1234'
        assert not form.validate()

# Test update user functionality
def test_update_user(client):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=DeprecationWarning)

        # Retrieve the user from the database
        user = User.query.filter_by(email='sunny@gmail.com').first()

        # Ensure that the user exists in the database
        assert user is not None, "User with email 'sunny@gmail.com' does not exist"

        # Update the user's information
        user.first_name = 'menuga_updated'
        user.last_name = 'sunny_updated'
        user.password = 'Sunny@123_updated'

        # Commit the changes to the database
        db.session.commit()

        # Send a request to update the user via the client
        response = client.post(f'/update_user/{user.id}', data={
            'first_name': 'menuga_updated',
            'last_name': 'sunny_updated',
            'email': 'sunny@gmail.com',  # Ensure email remains the same to avoid unique constraint violation
            'password': 'Sunny@123_updated'
        }, follow_redirects=True)

        # Check if the update was successful
        assert b'User updated successfully!' in response.data

# Test delete user functionality
def test_delete_user(client):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=DeprecationWarning)

        # Retrieve the user from the database
        user = User.query.filter_by(email='sunny@gmail.com').first()

        # Ensure that the user exists in the database
        assert user is not None, "User with email 'sunny@gmail.com' does not exist"

        # Send a request to delete the user via the client
        response = client.get(f'/delete_user/{user.id}', follow_redirects=True)

        # Check if the user was successfully deleted
        assert b'User deleted successfully!' in response.data
