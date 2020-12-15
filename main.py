#!/usr/bin/python

from Crypto.Cipher import AES
import sqlite3
import sys
import os.path

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
        rows = self.cursor.execute('SELECT username, password FROM password_manager WHERE website = ?', (website, )).fetchall()
        for row in rows:
            cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
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

    def update_master_password(self, master_password, new_master_password):
        if self.master_password != master_password:
            print('Wrong password! Try again!')
            return
        # when we change the master password we must re encrypt all data with the new password
        new_key = PasswordManagerUtil.__apply_padding(new_master_password, '\n').encode('utf8')
        decrypted_list = []
        rows = self.cursor.execute('SELECT website, username, password FROM password_manager').fetchall()
        if len(rows) > 0:
            for row in rows:
                cipher_dec = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
                decrypted_password = cipher_dec.decrypt(row[2]).decode('utf8')
                decrypted_list.append([row[0], row[1], decrypted_password])
        self.key = new_key
        self.master_password = new_master_password
        self.cursor.execute('UPDATE manager SET master_password = ?', (new_master_password, ))
        self.connection.commit()

        self.cursor.execute('DELETE FROM password_manager')
        self.connection.commit()
        for decrypted_row in decrypted_list:
            self.add_password(self.master_password, decrypted_row[0], decrypted_row[1], decrypted_row[2])

    def print_help(self):
        print('`-add` command has the following parameters: <website> <username> <password>')
        print('`-get` command has the following parameters: <website>')
        print('`-update` command has the following parameters: <website> <username> <new_password>')
        print('`-remove` command has the following parameters: <website>')
        print('`-list` command has no parameters')
        print('`-reset` command has no parameters')
        print('`-change_master_password` command has no parameters')
        print('`-help` command has no parameters')


def bind_master_password():
    # todo verifica daca exista baza de date
    if not os.path.exists('password_manager.db'):
        print("Baza de date nu exista!")
        return False
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    rows = cursor.execute('SELECT master_password FROM manager').fetchall()
    password_set = len([row for row in rows]) != 0
    if not password_set:
        print('It looks like you haven\'t set a master password!')
        master_password = input('Enter your password: ')
        cursor.execute('INSERT INTO manager (master_password) VALUES (?)', (master_password, ))
        connection.commit()
        print('Master password set successfully!')
        return master_password
    return rows[0][0]


if __name__ == '__main__':
    _master_password = bind_master_password()
    if not _master_password:
        print("Baza de date incorecta sau inexistenta!")
    else:
        pw_manager = PasswordManagerUtil(_master_password)

        if len(sys.argv) == 3:
            if sys.argv[2] == '-list':
                pw_manager.list_passwords(sys.argv[1])
            elif sys.argv[2] == '-help':
                pw_manager.print_help()
            elif sys.argv[2] == '-reset':
                pw_manager.delete_all_passwords(sys.argv[1])
            elif sys.argv[2] == '-change_master_password':
                if _master_password == sys.argv[1]:
                    new_master_password = input('Enter the new master password: ')
                    pw_manager.update_master_password(sys.argv[1], new_master_password)
                else:
                    print('Wrong password! Try again!')
            else:
                pw_manager.print_help()
        elif len(sys.argv) == 4:
            if sys.argv[2] == '-get':
                pw_manager.get_password(sys.argv[1], sys.argv[3])
            elif sys.argv[2] == '-remove':
                pw_manager.remove_password(sys.argv[1], sys.argv[3])
            else:
                pw_manager.print_help()
        elif len(sys.argv) == 6:
            if sys.argv[2] == '-add':
                pw_manager.add_password(sys.argv[1], sys.argv[3], sys.argv[4], sys.argv[5])
            elif sys.argv[2] == '-update':
                pw_manager.update_password(sys.argv[1], sys.argv[3], sys.argv[4], sys.argv[5])
            else:
                pw_manager.print_help()
        else:
            pw_manager.print_help()

