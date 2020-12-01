from Crypto.Cipher import AES
import sqlite3


class PasswordManagerUtil:
    def __init__(self, password_manager):
        self.password_manager = password_manager
        self.connection = sqlite3.connect('password_manager.db')
        self.cursor = self.connection.cursor()
        self.__iv = b'1122334455667788'

    @staticmethod
    def __apply_padding(string, value):
        while len(string) % 16 != 0:
            string += value
        return string

    def add_password(self, password_manager, website, username, password):
        if self.password_manager != password_manager:
            print('Wrong password! Try again!')
            return

        key = PasswordManagerUtil.__apply_padding(password_manager, '\n').encode('utf8')
        cipher = AES.new(key, mode=AES.MODE_CFB, iv=self.__iv)
        encrypted_password = cipher.encrypt(password.encode('utf8'))

        self.cursor.execute('INSERT INTO password_manager (website, username, password) VALUES (?, ?, ?)', (website, username, encrypted_password))
        self.connection.commit()

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

