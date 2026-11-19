import json
import html
from flask import make_response


def get_response(status, body):
    response = make_response(body, status)
    response.headers['Content-Type'] = 'application/json'
    return response


def error_handler(message, status=400):
    return get_response(status, json.dumps(dict(status="error", message=message)))


def html_decode(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    return html.unescape(data)


def json_loads(data):
    try:
        data = json.loads(html_decode(data))
    except ValueError as e:
        raise ValueError(str(e)) from e
    return data
