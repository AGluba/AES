from aes import *
import tkinter as tk
import string
from tkinter import filedialog as fd

fe = None
fed = None

def change_text(content):
   e1.delete(0, "end")
   e1.insert(0, content)

def open_text_file_to_encrypt():
    global fe
    filetypes = (
        ('All files', '*.*'),
        ('text files', '*.txt'),
        ('pdf files', '*.pdf')
    )
    fe = fd.askopenfile(filetypes=filetypes)

def open_text_file_to_decrypt():
    global fed
    filetypes = (
        ('All files', '*.*'),
        ('text files', '*.txt'),
        ('pdf files', '*.pdf')
    )
    fed = fd.askopenfile(filetypes=filetypes)
def check_key(*args):
    if len(key.get()) in [32, 48, 64] and all([(i in string.hexdigits) for i in key.get()]):
        if len(plain_text.get()) >= 1 or fe is not None:
            encrypt_button["state"] = "active"
    if len(key.get()) in [32, 48, 64] and all([(i in string.hexdigits) for i in key.get()]):
        if len(cipher_text.get()) >= 1 or fed is not None:
            decrypt_button["state"] = "active"
    else:
        encrypt_button["state"] = "disabled"
        decrypt_button["state"] = "disabled"

def encrypt():
    aes = AES(key.get())

    if fe is not None:
        file_name, file_extension = os.path.splitext(fe.name)
        operation_on_file(file_name+file_extension, file_name+"encrypted"+file_extension, aes, True)
    else:
        text = encrypt_message(plain_text.get(), aes)
        cipher_text.set(text)

def decrypt():
    aes = AES(key.get())

    if fed is not None:
        file_name, file_extension = os.path.splitext(fed.name)
        operation_on_file(file_name+file_extension, file_name+"decrypted"+file_extension, aes, False)
    else:
        text = decrypt_message(cipher_text.get(), aes)
        plain_text.set(text)

window = tk.Tk()
window.geometry("550x250")
window.title("AES")
window.resizable(False, False)

tk.Label(window, text="Enter the key", font="Courier").grid(row=0, column=0)

key = tk.StringVar(window)
e1 = tk.Entry(window, textvariable=key, width=66)
e1.grid(row=1, column=0)

button128 = tk.Button(window, text="128", width=4, command=lambda:change_text(generate_key(16)))
button192 = tk.Button(window, text="192", width=4, command=lambda:change_text(generate_key(24)))
button256 = tk.Button(window, text="256", width=4, command=lambda:change_text(generate_key(32)))
button128.grid(row=1, column=1, padx=(10, 5))
button192.grid(row=1, column=2, padx=(5, 5))
button256.grid(row=1, column=3, padx=(5, 10))

tk.Label(window, text="Plaintext", font="Courier").place(x=45, y=120)
plain_text = tk.StringVar(window)
plain_text_entry = tk.Entry(window, textvariable=plain_text, width=30)
plain_text_entry.place(x=10, y=150)

encrypt_button = tk.Button(window, text="Encrypt", width=15, height=1, state="disabled", command=encrypt)
encrypt_button.place(x=215, y=130)
decrypt_button = tk.Button(window, text="Decrypt", width=15, height=1, state="disabled", command=decrypt)
decrypt_button.place(x=215, y=160)

tk.Label(window, text="Ciphertext", font="Courier").place(x=385, y=120)
cipher_text = tk.StringVar(window)
cipher_text_entry = tk.Entry(window, textvariable=cipher_text, width=30)
cipher_text_entry.place(x=355, y=150)

open_button = tk.Button(window, text='Choose file to encrypt', command=open_text_file_to_encrypt)
open_button.place(x=210, y=100)
open_button2 = tk.Button(window, text='Choose file to decrypt', command=open_text_file_to_decrypt)
open_button2.place(x=210, y=190)

key.trace("w", check_key)
plain_text.trace("w", check_key)
cipher_text.trace("w", check_key)

window.mainloop()
