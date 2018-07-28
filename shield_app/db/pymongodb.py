import urllib
import logging
import datetime
from bson import ObjectId
from pymongo import MongoClient

from shield_app.utils import config


LOG = logging.getLogger(__name__)
DB_CONFIG = config.Config().database()


def mongo_connect():
    username = DB_CONFIG.get('username')
    password = DB_CONFIG.get('password')
    host = DB_CONFIG.get('host')
    port = DB_CONFIG.get('port')
    db_name = DB_CONFIG.get('database_name')
    auth_database = DB_CONFIG.get('auth_database')
    if username and password and auth_database:
        uri = "mongodb://%s:%s@%s:%s/%s" % (username, urllib.quote_plus(password), host, port, auth_database)
    else:
        uri = "mongodb://%s:%s" % (host, port)
    conn = MongoClient(uri)
    db = conn[db_name]
    return conn, db


class KeypairDBAPI(object):
    def create_keypair(self, data):
        try:
            conn, client = mongo_connect()
            data['created_at'] = datetime.datetime.utcnow()
            result = client.keypair.insert(data)
            conn.close()
            return result
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def get_keypair(self, query):
        try:
            conn, client = mongo_connect()
            result = client.keypair.find_one(query)
            conn.close()
            return result
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)


class CertificatesDBAPI(object):
    def create_certificates(self, data):
        try:
            conn, client = mongo_connect()
            data['created_at'] = datetime.datetime.utcnow()
            result = client.certificate.insert(data)
            conn.close()
            return result
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def get_certificate(self, query):
        try:
            conn, client = mongo_connect()
            result = client.certificate.find_one(query)
            conn.close()
            return result
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def get_certificates(self, query, skip_val=0, limit=None):
        try:
            conn, client = mongo_connect()
            if limit:
                result = client.certificate.find(query).skip(skip_val).limit(limit).sort("_id", -1)
            else:
                result = client.certificate.find(query).sort("_id", -1)
            conn.close()
            return result
        except Exception as error:
            LOG.error(error.message)
            raise Exception(error.message)

    def delete(self, cert_id, data):
        try:
            conn, client = mongo_connect()
            result = client.certificate.update({'_id': ObjectId(cert_id)}, {"$set": data})
            conn.close()
            return result
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)
