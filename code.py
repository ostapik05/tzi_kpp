import struct

class KeyScheduler:
    def __init__(self, key):
        self.key = key
        self.subkeys = self.generate_subkeys()

    def generate_subkeys(self):
        # Генеруємо 16 підключів на основі ключа
        subkeys = []
        for i in range(16):
            subkey = (self.key + i * 123456) & 0xFFFFFFFF  # Спрощене створення підключа
            subkeys.append(subkey)
        return subkeys

class CASTEncryptor:
    def __init__(self, key):
        self.key_scheduler = KeyScheduler(key)

    def F(self, half_block, subkey):
        # Реалізуємо просту функцію F
        result = (half_block ^ subkey) + (half_block & subkey)
        return result & 0xFFFFFFFF

    def encrypt_block(self, block):
        L, R = struct.unpack(">II", block)  # Розбиваємо блок на дві половини по 32 біти
        for i in range(16):
            subkey = self.key_scheduler.subkeys[i]
            temp = self.F(R, subkey)
            L, R = R, (L ^ temp) & 0xFFFFFFFF
        return struct.pack(">II", R, L)  # Після завершення раундів об'єднуємо половини

    def decrypt_block(self, block):
        R, L = struct.unpack(">II", block)  # Зворотна операція розбиття
        for i in reversed(range(16)):
            subkey = self.key_scheduler.subkeys[i]
            temp = self.F(L, subkey)
            R, L = L, (R ^ temp) & 0xFFFFFFFF
        return struct.pack(">II", L, R)

class BlockProcessor:
    def __init__(self, data, block_size=8):
        self.data = data
        self.block_size = block_size

    def pad_data(self):
        padding_needed = self.block_size - len(self.data) % self.block_size
        return self.data + bytes([padding_needed] * padding_needed)  # Заповнення за стандартом PKCS7

    def unpad_data(self, padded_data):
        padding_len = padded_data[-1]
        return padded_data[:-padding_len]

    def split_into_blocks(self, padded_data):
        return [padded_data[i:i + self.block_size] for i in range(0, len(padded_data), self.block_size)]

    def combine_blocks(self, blocks):
        return b''.join(blocks)


class CASTCipherSystem:
    def __init__(self, key):
        self.encryptor = CASTEncryptor(key)

    def encrypt(self, plaintext):
        processor = BlockProcessor(plaintext)
        padded_data = processor.pad_data()
        blocks = processor.split_into_blocks(padded_data)
        encrypted_blocks = [self.encryptor.encrypt_block(block) for block in blocks]
        return processor.combine_blocks(encrypted_blocks)

    def decrypt(self, ciphertext):
        processor = BlockProcessor(ciphertext)
        blocks = processor.split_into_blocks(ciphertext)
        decrypted_blocks = [self.encryptor.decrypt_block(block) for block in blocks]
        decrypted_data = processor.combine_blocks(decrypted_blocks)
        return processor.unpad_data(decrypted_data)


# Використання системи шифрування CAST
key = 0x1A2B3C4D  # Початковий ключ
cipher_system = CASTCipherSystem(key)

# Вихідний текст для шифрування
plaintext = b"Hello, World!"
print("Original:", plaintext)

# Шифрування
encrypted_text = cipher_system.encrypt(plaintext)
print("Encrypted:", encrypted_text)

# Розшифрування
decrypted_text = cipher_system.decrypt(encrypted_text)
print("Decrypted:", decrypted_text)
