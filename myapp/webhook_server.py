from flask import Flask, request
from flask_mail import Mail, Message

app = Flask(__name__)

# Configure email settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your email provider
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'elsythomas36987@gmail.com'
app.config['MAIL_PASSWORD'] = 'ncjw nahp asvy vocr'
app.config['MAIL_DEFAULT_SENDER'] = 'elsythomas36987@gmail.com'

mail = Mail(app)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if 'commits' in data:
        msg = Message(
            subject="New GitHub Push",
            recipients=["elsythomas36987@gmail.com"],
            body=f"Repository: {data['repository']['full_name']}\n"
                 f"Pushed by: {data['pusher']['name']}\n"
                 f"Commit Message: {data['head_commit']['message']}"
        )
        mail.send(msg)
    return '', 200

if __name__ == '__main__':
    app.run(port=5000)
