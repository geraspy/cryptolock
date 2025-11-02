import hashlib
from cryptography.fernet import Fernet
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

KDF_SALT = b'a_very_secure_and_random_salt_for_kdf'

def encrypt_password(password: str, key: bytes) -> bytes:
    f = Fernet(key)
    token = f.encrypt(password.encode('utf-8'))
    return token

def decrypt_password(encrypted_data: bytes, key: bytes) -> str:
    try:
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Ошибка дешифрования: {e}")
        return "Не удалось расшифровать"

def load_vault():
    try:
        with open("vault.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("🚨 Внимание: Файл vault.json поврежден или пуст. Создаем новый.")
        return {}

def save_vault(vault_data):
    with open("vault.json", "w") as f:
        json.dump(vault_data, f, indent=4)

while True:
    try:
        hallo = int(
            input("Введите:\n1. Для доступа к паролям\n(приготовьте мастер-пароль) \n2. Создать мастер-пароль\n"))
        break
    except ValueError:
        print("Вы ввели не число! Попробуйте снова.")

if hallo == 1:
    try:
        with open("master.txt", "r") as f:
            stored_hash = f.read()

        if stored_hash == "":
            print("Сначала необходимо создать мастер-пароль")
            exit()

        while True:
            try:
                user_input_master = int(input("Введите свой мастер-пароль:"))
                break
            except ValueError:
                print("Вы ввели не число! Попробуйте снова.")

        hashed_attempt = str(user_input_master).encode('utf-8')
        hashed_attempter = hashlib.sha256(hashed_attempt).hexdigest()

        if hashed_attempter == stored_hash:
            print("✅ Доступ разрешён!")

            master_password_bytes = str(user_input_master).encode('utf-8')

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=KDF_SALT,
                iterations=480000,
                backend=default_backend()
            )

            key_32_bytes = kdf.derive(master_password_bytes)
            FERNET_KEY = base64.urlsafe_b64encode(key_32_bytes)
            print("🔑 Криптографический ключ готов.")

            while True:
                print("\n--- МЕНЮ ХРАНИЛИЩА ---")
                print("1. Добавить новый пароль")
                print("2. Просмотреть все пароли")
                print("3. Выйти")

                try:
                    choice = int(input("Ваш выбор: "))

                    if choice == 1:
                        vault = load_vault()
                        service_name = input("Введите имя сервиса (например, Google): ")
                        password = input("Введите пароль для этого сервиса: ")

                        encrypted_bytes = encrypt_password(password, FERNET_KEY)
                        vault[service_name] = encrypted_bytes.decode('utf-8')

                        save_vault(vault)
                        print(f"✅ Пароль для '{service_name}' сохранен (зашифрован).")

                    elif choice == 2:
                        vault = load_vault()

                        if not vault:
                            print("Хранилище пусто. Сначала добавьте пароль.")
                            continue

                        print("\n--- ВАШИ ПАРОЛИ (Дешифровано) ---")
                        for service, encrypted_token_str in vault.items():
                            try:
                                encrypted_bytes = encrypted_token_str.encode('utf-8')
                                decrypted_password = decrypt_password(encrypted_bytes, FERNET_KEY)
                                print(f"Сервис: {service.ljust(15)} | Пароль: {decrypted_password}")
                            except Exception:
                                print(f"Сервис: {service.ljust(15)} | Пароль: ❌ Ошибка дешифрования")

                        print("---------------------------------")

                    elif choice == 3:
                        print("Выход из хранилища. До свидания!")
                        break

                    else:
                        print("Неверный выбор. Попробуйте снова.")

                except ValueError:
                    print("Неверный ввод. Введите номер пункта меню.")
        else:
            print("❌ Доступ отклонён!")

    except FileNotFoundError:
        print("Сначала необходимо создать мастер-пароль")
        exit()

elif hallo == 2:
    while True:
        try:
            create_master = int(input("Введите придуманный числовой мастер-пароль:"))
            print(f"Запомните или запишите свой мастер-пароль - {create_master}")

            str_master = str(create_master).encode('utf-8')
            hashed_master = hashlib.sha256(str_master).hexdigest()

            with open("master.txt", "w") as f:
                f.write(hashed_master)
                break
        except ValueError:
            print("Вы ввели не число! Попробуйте снова.")

else:
    pass