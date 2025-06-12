import flet as ft
import sqlite3
from cryptography.fernet import Fernet
import os
import bcrypt
import logging

logging.basicConfig(
    filename='app.log', 
    level=logging.INFO, 
    encoding='utf-8',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DatabaseManager:
    def __init__(self):
        self.init_db()

    def init_db(self) -> None:
        db = sqlite3.connect('database.db')
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password TEXT NOT NULL )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               password TEXT NOT NULL )
        ''')
    
        db.commit()
        db.close()

    def get_master_password(self):
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT password FROM master_password LIMIT 1')
            result = cursor.fetchone()
            return result[0] if result else None

    def set_master_password(self, password):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM master_password') 
            cursor.execute('INSERT INTO master_password (password) VALUES (?)', (hashed,))
            db.commit()
    
    def check_master_password(self, input_password):
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT password FROM master_password LIMIT 1')
            result = cursor.fetchone()

        if not result:
            return False
        return bcrypt.checkpw(input_password.encode(), result[0])

    def get_all_passwords(self):
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, name, password FROM passwords')
            return cursor.fetchall()
        
    def add_password(self, name, password):
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('INSERT INTO passwords (name, password) VALUES (?, ?)', 
                          (name, password))
            db.commit()

    def delete_password(self, password_id):
        with sqlite3.connect('database.db') as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
            db.commit()


class CryptoManager:
    def __init__(self):
        self.key = self.load_or_create_key()
        self.fernet = Fernet(self.key)

    def load_or_create_key(self):
        if os.path.exists('secret.key'):
            with open('secret.key', 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open('secret.key', 'wb') as f:
                f.write(key)
            return key
        
    def encrypt(self, data: str) -> bytes:
        return self.fernet.encrypt(data.encode())
    
    def decrypt(self, data: bytes) -> str:
        return self.fernet.decrypt(data).decode()


class PasswordManagerApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Password Manager"
        self.db = DatabaseManager()
        self.crypto = CryptoManager()

        self.setup_ui()
        self.load_initial_state()

    def setup_ui(self):
        self.name_field = ft.TextField(width=250, visible=False)
        self.password_field = ft.TextField(width=300, visible=False)
        self.passwords_list = ft.Column(scroll=True)

        self.input_field = ft.TextField(label="Введите текст", width=300, password=True)
        self.add_master_password_input = ft.TextField(label="Введите master", width=300, visible=False, password=True)

        self.submit_btn = ft.ElevatedButton("Проверить", on_click=self.check_input, visible=False)
        self.submit_master_btn = ft.ElevatedButton("Задать", on_click=self.add_master_password, visible=False)
        self.add_button = ft.Button(text='Добавить', on_click=self.add_password, visible=False)


        self.container_passwords = ft.Container(
            content=self.passwords_list,
            expand=True,
            visible=False
        )

        self.page.add(
            ft.Row(
                [
                    self.name_field,
                    self.password_field,
                    self.input_field,
                    self.add_master_password_input,
                    self.submit_btn,
                    self.submit_master_btn,
                    self.add_button,
                ],
                alignment=ft.MainAxisAlignment.CENTER
            ),
            self.container_passwords,
        )

    def load_initial_state(self):
        master_password = self.db.get_master_password()

        if not master_password:
            self.submit_btn.visible = False
            self.input_field.visible = False
            self.add_master_password_input.visible = True
            self.submit_master_btn.visible = True
        else:
            self.submit_btn.visible = True
            self.input_field.visible = True
            self.add_master_password_input.visible = False
            self.submit_master_btn.visible = False

        self.load_passwords()
        self.page.update()

    def add_master_password(self, e):
        if self.add_master_password_input.value:
            self.db.set_master_password(self.add_master_password_input.value)
            self.input_field.visible = True
            self.submit_btn.visible = True
            self.add_master_password_input.visible = False
            self.submit_master_btn.visible = False
            self.page.update()

    def check_input(self, e):
        if self.db.check_master_password(self.input_field.value):
            self.input_field.visible = False
            self.submit_btn.visible = False

            self.name_field.visible = True
            self.password_field.visible = True
            self.passwords_list.visible = True
            self.container_passwords.visible = True
            self.add_button.visible = True
        else:
            print("Неверный пароль!")

        self.page.update()

    def load_passwords(self):
        self.passwords_list.controls.clear()

        try:
            for row in self.db.get_all_passwords():
                id, name_val, password_val = row
                name_decrypt = self.crypto.decrypt(name_val)
                password_decrypt = self.crypto.decrypt(password_val)
                password_block = self.create_password_block(id, name_decrypt, password_decrypt)
                self.passwords_list.controls.append(password_block)
        except Exception as e:
            print(f"Ошибка: {e}")

        self.page.update()
                
    def create_password_block(self, id, name_val, password_val):
        return ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.ListTile(
                            title=ft.Text(name_val, selectable=True),
                            subtitle=ft.Text(password_val, selectable=True),
                        ),
                        ft.Row(
                        [
                            ft.TextButton('Удалить', on_click = lambda e: self.delete_password(e, id))
                        ],
                        alignment=ft.MainAxisAlignment.END
                    )
                ])
            )
        )
    
    def add_password(self, e):
        if self.name_field.value and self.password_field.value:
            name_crypt = self.crypto.encrypt(self.name_field.value)
            password_crypt = self.crypto.encrypt(self.password_field.value)

            self.db.add_password(name_crypt, password_crypt)

            self.name_field.value = ''
            self.password_field.value = ''
            self.load_passwords()

    def delete_password(self, e, password_id):
        self.db.delete_password(password_id)
        self.load_passwords()
    

def main(page: ft.Page):
    app = PasswordManagerApp(page)


ft.app(target=main)