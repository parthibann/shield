from flask_restful import request
from flask_restful import Resource
from flask import send_file
import StringIO

from shield_app.utils.route_utils import error_handler
from shield_app.utils.route_utils import get_response
from shield_app.utils.route_utils import json_loads
from shield_app.api.actions import CertificateActions


class Certificate(Resource):
    def __init__(self):
        self.actions = CertificateActions()

    def post(self):
        try:
            ui_data = request.form.to_dict()
            backend_data = request.get_data()
            req_body = ui_data if ui_data else json_loads(backend_data)
            status, res_body = self.actions.create(req_body)
            return get_response(status, res_body)
        except Exception as e:
            print e.message
            return error_handler(e.message)

    def get(self, certid=None, type=None, resource_id=None):
        try:
            if certid:
                status, res_body = self.actions.view(certid)
            elif resource_id and type:
                # filename = self.actions.download(resource_id, type)
                # if filename:
                #     return send_file(filename, as_attachment=True)
                # else:
                #     raise Exception('Requested resource not found.')
                if type == 'cert':
                    filename = 'certificate.pem'
                elif type == 'private_key':
                    filename = 'private_key.pem'
                elif type == 'public_key':
                    filename = 'public_key.pem'
                else:
                    filename = 'error'
                strIO = StringIO.StringIO()
                data = self.actions.download(resource_id, type)
                strIO.write(data)
                strIO.seek(0)
                return send_file(strIO, attachment_filename=filename, as_attachment=True)
            else:
                status, res_body = self.actions.list(request.args)
            return get_response(status, res_body)
        except Exception as e:
            return error_handler(e.message)

    def delete(self, certid):
        try:
            status, res_body = self.actions.delete(certid)
            return get_response(status, res_body)
        except Exception as e:
            return error_handler(e.message)
