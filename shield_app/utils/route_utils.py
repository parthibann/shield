import json
from flask import make_response
from HTMLParser import HTMLParser


def get_response(status, body):
    response = make_response(str(body), status)
    response.headers['Content-Type'] = 'application/json'
    return response


def error_handler(message, status=400):
    return get_response(status, json.dumps(dict(status="error", message=message)).encode('utf-8'))


def html_decode(data):
    parser = HTMLParser()
    return parser.unescape(data)


def json_loads(data):
    try:
        data = json.loads(html_decode(data))
    except ValueError as e:
        raise ValueError(e.message)
    return data
