from flask import Flask
from hidden_service import run_hidden_service

app = Flask(__name__)

html_code = """
This is an example text
"""

@app.route("/")
def index():
    return(html_code)

run_hidden_service(control_port=20000, application=app, leave_address_alive=True)
