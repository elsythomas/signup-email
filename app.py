from flask import Flask

# Create the Flask app
app = Flask(__name__)

# Define the route and corresponding function
@app.route('/webhook_server/')
def your_function():
    return "Hello, World!"

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
