import os

from flask import Flask
from flask import render_template
from flask_restful import Api

from shield_app.utils.route_utils import error_handler
from shield_app.api.route import Certificate

current_path = os.path.dirname(os.path.abspath(__file__))
ui_path = os.path.join(current_path, os.pardir, "shield_ui")
app = Flask("shield", template_folder=ui_path, static_folder=ui_path + os.sep + 'static')


app.register_error_handler(Exception, error_handler)
api = Api(app)

api.add_resource(Certificate, '/v1/certifiates', '/v1/certifiates/<certid>',
                 '/v1/certificates/download/<type>/<resource_id>')


@app.route('/')
def homepage():
    return render_template('index.html')
