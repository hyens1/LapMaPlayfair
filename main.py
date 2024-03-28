import tkinter as tk
from tkinter import messagebox

def preprocess(text):
    processed_text = ""
    for char in text:
        if char.isalpha():
            processed_text += char.lower()
    return processed_text

def create_key_table(key):
    key = key.replace('j', 'i')  # Loại bỏ 'j' và thay thế bằng 'i'
    key_table = [[''] * 5 for _ in range(5)]  # Khởi tạo key_table với kích thước 5x5
    is_present = [False] * 26
    row, col = 0, 0
    for char in key:
        if not is_present[ord(char) - ord('a')]:
            key_table[row][col] = char
            is_present[ord(char) - ord('a')] = True
            col += 1
            if col == 5:
                col = 0
                row += 1
    for i in range(26):
        if not is_present[i]:
            key_table[row][col] = chr(i + ord('a'))
            is_present[i] = True
            col += 1
            if col == 5:
                col = 0
                row += 1
            if row == 5:  # Đảm bảo không vượt quá kích thước của key_table
                break
    return key_table


def encrypt(plaintext, key_table):
    ciphertext = ""
    i = 0
    while i < len(plaintext):
        char1, char2 = plaintext[i], ''
        if i + 1 < len(plaintext):
            char2 = plaintext[i + 1]
        else:
            char2 = 'x' if plaintext[i] != 'x' else 'z'
            i -= 1
        row1, col1, row2, col2 = 0, 0, 0, 0
        for row in range(5):
            for col in range(5):
                if key_table[row][col] == char1:
                    row1, col1 = row, col
                if key_table[row][col] == char2:
                    row2, col2 = row, col
        if row1 == row2:
            ciphertext += key_table[row1][(col1 + 1) % 5]
            ciphertext += key_table[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += key_table[(row1 + 1) % 5][col1]
            ciphertext += key_table[(row2 + 1) % 5][col2]
        else:
            ciphertext += key_table[row1][col2]
            ciphertext += key_table[row2][col1]
        i += 2
    return ciphertext

def decrypt(ciphertext, key_table):
    plaintext = ""
    i = 0
    while i < len(ciphertext):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1, row2, col2 = 0, 0, 0, 0
        for row in range(5):
            for col in range(5):
                if key_table[row][col] == char1:
                    row1, col1 = row, col
                if key_table[row][col] == char2:
                    row2, col2 = row, col
        if row1 == row2:
            plaintext += key_table[row1][(col1 - 1) % 5]
            plaintext += key_table[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += key_table[(row1 - 1) % 5][col1]
            plaintext += key_table[(row2 - 1) % 5][col2]
        else:
            plaintext += key_table[row1][col2]
            plaintext += key_table[row2][col1]
        i += 2
    return plaintext

def clear_text(entry):
    entry.delete(0, tk.END)

def on_encrypt():
    key = key_entry.get()
    plaintext = plaintext_entry.get()
    key_table = create_key_table(key)
    plaintext = preprocess(plaintext)
    ciphertext = encrypt(plaintext, key_table)
    ciphertext_entry.delete(0, tk.END)
    ciphertext_entry.insert(0, ciphertext)

def on_decrypt():
    key = key_entry.get()
    ciphertext = ciphertext_entry.get()
    key_table = create_key_table(key)
    decrypted_text = decrypt(ciphertext, key_table)
    decrypted_entry.delete(0, tk.END)
    decrypted_entry.insert(0, decrypted_text)

# GUI
root = tk.Tk()
root.title("Playfair Cipher")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# Key
key_label = tk.Label(frame, text="Key:")
key_label.grid(row=0, column=0, sticky="e")
key_entry = tk.Entry(frame)
key_entry.grid(row=0, column=1, padx=5, pady=5)

# Plaintext
plaintext_label = tk.Label(frame, text="Plaintext:")
plaintext_label.grid(row=1, column=0, sticky="e")
plaintext_entry = tk.Entry(frame)
plaintext_entry.grid(row=1, column=1, padx=5, pady=5)

# Encrypt Button
encrypt_button = tk.Button(frame, text="Encrypt", command=on_encrypt)
encrypt_button.grid(row=2, column=0, columnspan=2, pady=5)

# Ciphertext
ciphertext_label = tk.Label(frame, text="Ciphertext:")
ciphertext_label.grid(row=3, column=0, sticky="e")
ciphertext_entry = tk.Entry(frame)
ciphertext_entry.grid(row=3, column=1, padx=5, pady=5)

# Decrypt Button
decrypt_button = tk.Button(frame, text="Decrypt", command=on_decrypt)
decrypt_button.grid(row=4, column=0, columnspan=2, pady=5)

# Decrypted text
decrypted_label = tk.Label(frame, text="Decrypted Text:")
decrypted_label.grid(row=5, column=0, sticky="e")
decrypted_entry = tk.Entry(frame)
decrypted_entry.grid(row=5, column=1, padx=5, pady=5)

root.mainloop()
