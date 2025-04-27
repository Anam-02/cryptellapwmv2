from flask import Flask
from routes import routes
from datetime import timedelta
from flask import Flask

app = Flask(__name__)


# Secret key for session management (should be more secure in production)
app.secret_key = "your_secret"

# Set session lifetime — user is logged out after 2 minutes of inactivity
app.permanent_session_lifetime = timedelta(minutes=2)

# Register all routes from routes.py
app.register_blueprint(routes)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)