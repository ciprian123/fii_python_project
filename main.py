from Crypto.Cipher import AES
import sqlite3

class PasswordManagerUtil:
    def __init__(self, password_manager):
        self.password_manager = password_manager
        self.connection = sqlite3.connect('pwmanager.db')
        self.cursor = self.connection.cursor()

    def add_password(self, password_manager, website, username, password):
        pass

    def get_password(self, password_manager, website):
        pass

    def update_password(self, password_manager, website, username, password):
        pass

    def remove_password(self, password_manager, website):
        pass

    def list_passwords(self, password_manager):
        pass

    def delete_all_passwords(self, password_manager):
        pass

    def print_help(self):
        pass
