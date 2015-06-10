import sqlite3
import os


class NoSamples(Exception):
    pass


class SQLiteDatabase():
    def __init__(self, db_filename):
        init_db = False
        if not os.path.isfile(db_filename):
            init_db = True
        self.__connection = sqlite3.connect(db_filename)

        if init_db:
            self.initialize_database()

    def initialize_database(self):
        cursor = self.__connection.cursor()
        try:
            cursor.execute('CREATE TABLE samples (sha1 TEXT UNIQUE, filename TEXT, architecture INTEGER)')
        except sqlite3.OperationalError, sqlite3.IntegrityError:
            pass
        cursor.close()
        self.__connection.commit()

    def insert(self, sha1, filename, architecture):
        cursor = self.__connection.cursor()
        try:
            cursor.execute('INSERT INTO samples VALUES(?, ?, ?)', (sha1, filename, architecture))
        except sqlite3.OperationalError, sqlite3.IntegrityError:
            pass
        cursor.close()
        self.__connection.commit()

    def delete(self, sha1):
        cursor = self.__connection.cursor()
        try:
            cursor.execute('DELETE FROM samples WHERE sha1 = ?', (sha1,))
        except sqlite3.OperationalError:
            pass
        cursor.close()
        self.__connection.commit()

    def select(self, sha1):
        result = None
        cursor = self.__connection.cursor()
        try:
            cursor.execute('SELECT * FROM samples WHERE sha1 = ?', (sha1,))
            result = cursor.fetchone()
        except sqlite3.OperationalError:
            pass
        cursor.close()
        self.__connection.commit()

        return result

    def exists(self, sha1):
        if self.select(sha1):
            return True
        return False

    def get_next(self, architecture):
        result = None
        cursor = self.__connection.cursor()
        try:
            cursor.execute('SELECT * FROM samples WHERE architecture = ? OR architecture = 0  ', (architecture,))
            result = cursor.fetchone()
        except sqlite3.OperationalError:
            pass
        cursor.close()

        if result:
            self.delete(result[0])
            self.__connection.commit()
            return result[0], result[1]
        self.__connection.commit()
        raise NoSamples()

    def close(self):
        self.__connection.close()