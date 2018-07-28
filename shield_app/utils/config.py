import os
from configparser import NoOptionError
from configparser import NoSectionError
from configparser import ConfigParser


current_path = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(current_path, os.pardir, os.pardir, "config")
conf_file = path + os.sep + 'shield.conf'


class Config(object):
    def __init__(self):
        self.config = ConfigParser()
        self.config.read(conf_file)

    def database(self):
        database = dict()
        database['host'] = self.config.get("database", "host")
        database['port'] = self.config.get("database", "port")
        database['database_name'] = self.config.get("database", "database_name")
        try:
            database['username'] = self.config.get("database", "username")
            database['password'] = self.config.get("database", "password")
            database['auth_database'] = self.config.get("database", "auth_database")
        except NoOptionError, NoSectionError:
            database['username'] = None
            database['password'] = None
            database['auth_database'] = None
        except Exception as error:
            raise Exception(error.message)
        return database
