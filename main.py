#!/usr/bin/python

from Crypto.Cipher import AES
import sqlite3
import sys


class PasswordManagerUtil:
    def __init__(self, master_password):
        self.master_password = master_password
        self.connection = sqlite3.connect('password_manager.db')
        self.cursor = self.connection.cursor()
        self.key = PasswordManagerUtil.__apply_padding(master_password, '\n').encode('utf8')
        self.__iv = b'1122334455667788'

    @staticmethod
    def __apply_padding(string, value):
        while len(string) % 16 != 0:
            string += value
        return string

    def add_password(self, password_manager, website, username, password):
        if self.master_password != password_manager:
            print('Wrong password! Try again!')
            return
        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        encrypted_password = cipher.encrypt(password.encode('utf8'))
        self.cursor.execute('INSERT INTO password_manager (website, username, password) VALUES (?, ?, ?)', (website, username, encrypted_password))
        self.connection.commit()
        print('PASSWORD SAVED SUCCESSFULLY!')

    def get_password(self, password_manager, website):
        if self.master_password != password_manager:
            print('Wrong password! Try again!')
            return
        print('USERNAME AND PASSWORDS FOR WEBSITE:', website)
        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        rows = self.cursor.execute('SELECT username, password FROM password_manager WHERE website = ?', (website, )).fetchall()
        for row in rows:
            decrypted_password = cipher.decrypt(row[1]).decode('utf8')
            print(f'USERNAME: {row[0]}  :  PASSWORD: {decrypted_password}')
        if len(rows) == 0:
            print(f'NO PASSWORD FOR WEBSITE {website} :(')

    def update_password(self, password_manager, website, username, password):
        if self.master_password != password_manager:
            print('Wrong password! Try again!')
            return
        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        encrypted_password = cipher.encrypt(password.encode('utf8'))
        self.cursor.execute('UPDATE password_manager SET website = ?, username = ?, password = ? WHERE website = ? AND username = ?', (website, username, encrypted_password, website, username))
        self.connection.commit()
        print('PASSWORD UPDATED SUCCESSFULLY!')

    def remove_password(self, password_manager, website):
        if self.master_password != password_manager:
            print('Wrong password! Try again!')
            return
        self.cursor.execute('DELETE FROM password_manager WHERE website = ?', (website, ))
        self.connection.commit()
        print('PASSWORD DELETED SUCCESSFULLY!')

    def list_passwords(self, password_manager):
        if self.master_password != password_manager:
            print('Wrong password! Try again!')
            return
        print('LISTING PASSWORDS... ')
        rows = self.cursor.execute('SELECT website, username, password FROM password_manager').fetchall()
        counter = 0
        for row in list(rows):
            cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
            decrypted_password = cipher.decrypt(row[2]).decode('utf8')
            print(f'WEBSITE: {row[0]}  |   USERNAME: {row[1]}   |   PASSWORD: {decrypted_password}')
        if len(rows) == 0:
            print('NO PASSWORDS SO FAR :(')

    def delete_all_passwords(self, master_password):
        if self.master_password != master_password:
            print('Wrong password! Try again!')
            return
        print('WARNING, THIS OPERATION WILL DELETE ALL YOU PASSWORDS!')
        input_password = input('Enter your master password to confirm: ')
        if self.master_password != input_password:
            print('Wrong password, exiting...')
            return
        self.cursor.execute('DELETE FROM password_manager')
        self.connection.commit()
        print('DATA DELETED SUCCESSFULLY!')

    def print_help(self):
        print('`-add` command has the following parameters: <website> <username> <password>')
        print('`-get` command has the following parameters: <website>')
        print('`-update` command has the following parameters: <website> <username> <new_password>')
        print('`-remove` command has the following parameters: <website>')
        print('`-list` command has no parameters')


if __name__ == '__main__':
    pw_manager = PasswordManagerUtil('112233')
    pw_manager.add_password('112233', 'gmail.com', 'ciprian.ursulean5@gmail.com', '12311223344556677')
    pw_manager.add_password('112233', 'steam.com', 'ciprian.ursulean5@gmail.com', 'dota2islife')
    # pw_manager.update_password('112233', 'github.com', 'ciprian.ursulean5@gmail.com', 'parolahehehe')
    # pw_manager.remove_password('112233', 'github.com')
    # pw_manager.get_password('112233', 'gmail.com')
    # pw_manager.get_password('112233', 'github.com')
    pw_manager.list_passwords('112233')
    # pw_manager.print_help()
    # pw_manager.delete_all_passwords('112233')
