import hashlib
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

KDF_SALT = b'a_very_secure_and_random_salt_for_kdf'
MASTER_FILE = Path("master.txt")
VAULT_FILE = Path("vault.json")


def get_int_input(prompt):
    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print("Ошибка: введите число!")


def hash_password(password):
    return hashlib.sha256(str(password).encode()).hexdigest()


def derive_key(master_password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=KDF_SALT,
                     iterations=480000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(str(master_password).encode()))


def load_vault():
    try:
        return json.loads(VAULT_FILE.read_text()) if VAULT_FILE.exists() else {}
    except json.JSONDecodeError:
        print("⚠️ Файл поврежден, создаем новый.")
        return {}


def save_vault(vault):
    VAULT_FILE.write_text(json.dumps(vault, indent=4))


def encrypt(password, key):
    return Fernet(key).encrypt(password.encode()).decode()


def decrypt(encrypted, key):
    try:
        return Fernet(key).decrypt(encrypted.encode()).decode()
    except:
        return "❌ Ошибка"


def create_master():
    master = get_int_input("Создайте числовой мастер-пароль: ")
    print(f"⚠️ Запомните: {master}")
    MASTER_FILE.write_text(hash_password(master))


def access_vault():
    if not MASTER_FILE.exists() or not MASTER_FILE.read_text():
        print("❌ Сначала создайте мастер-пароль!")
        return

    master = get_int_input("Введите мастер-пароль: ")
    if hash_password(master) != MASTER_FILE.read_text():
        print("❌ Доступ запрещен!")
        return

    print("✅ Доступ разрешен!")
    key = derive_key(master)

    while True:
        print("\n1. Добавить пароль\n2. Показать пароли\n3. Выход")
        choice = get_int_input("Выбор: ")

        if choice == 1:
            vault = load_vault()
            service = input("Сервис: ")
            password = input("Пароль: ")
            vault[service] = encrypt(password, key)
            save_vault(vault)
            print(f"✅ Сохранено для '{service}'")

        elif choice == 2:
            vault = load_vault()
            if not vault:
                print("Хранилище пусто")
                continue
            print("\n--- ПАРОЛИ ---")
            for service, enc_pass in vault.items():
                print(f"{service:15} | {decrypt(enc_pass, key)}")

        elif choice == 3:
            print("До свидания!")
            break


# Главное меню
choice = get_int_input("1. Войти\n2. Создать мастер-пароль\nВыбор: ")
access_vault() if choice == 1 else create_master() if choice == 2 else None