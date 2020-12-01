from Crypto.Cipher import AES
import sqlite3


class PasswordManagerUtil:
    def __init__(self, password_manager):
        self.password_manager = password_manager
        self.connection = sqlite3.connect('password_manager.db')
        self.cursor = self.connection.cursor()
        self.key = PasswordManagerUtil.__apply_padding(password_manager, '\n').encode('utf8')
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

        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        encrypted_password = cipher.encrypt(password.encode('utf8'))

        self.cursor.execute('INSERT INTO password_manager (website, username, password) VALUES (?, ?, ?)', (website, username, encrypted_password))
        self.connection.commit()

    def get_password(self, password_manager, website):
        if self.password_manager != password_manager:
            print('Wrong password! Try again!')
            return
        print('USERNAME AND PASSWORDS FOR WEBSITE:', website)
        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        rows = self.cursor.execute('SELECT username, password FROM password_manager WHERE website = ?', (website, ))
        for row in rows:
            decrypted_password = cipher.decrypt(row[1]).decode('utf8')
            print(f'USERNAME: {row[0]}  :  PASSWORD: {decrypted_password}')

    def update_password(self, password_manager, website, username, password):
        if self.password_manager != password_manager:
            print('Wrong password! Try again!')
            return

        cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.__iv)
        encrypted_password = cipher.encrypt(password.encode('utf8'))
        self.cursor.execute('UPDATE password_manager SET website = ?, username = ?, password = ? WHERE website = ? AND username = ?', (website, username, encrypted_password, website, username))
        self.connection.commit()

    def remove_password(self, password_manager, website):
        pass

    def list_passwords(self, password_manager):
        pass

    def delete_all_passwords(self, password_manager):
        pass

    def print_help(self):
        pass


if __name__ == '__main__':
    pw_manager = PasswordManagerUtil('112233')
    # pw_manager.add_password('112233', 'gmail.com', 'ciprian.ursulean5@gmail.com', '12311223344556677')
    # pw_manager.add_password('112233', 'github.com', 'ciprian.ursulean5@gmail.com', 'githubhehehe')
    # pw_manager.update_password('112233', 'github.com', 'ciprian.ursulean5@gmail.com', 'parolahehehe')
    pw_manager.get_password('112233', 'github.com')
