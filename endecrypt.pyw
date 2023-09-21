import tkinter as tk
from tkinter import ttk


def encrypt(plaintext, password):
    encrypted = []
    for i in range(len(plaintext)):
        encrypted_char = ord(plaintext[i]) ^ ord(password[i % len(password)])
        encrypted.append(encrypted_char)
    change_text(output_text,bytes(encrypted).hex())

def decrypt(encrypted_bytes, password):

    decrypted = []
    for i in range(len(encrypted_bytes)):
        decrypted_char = encrypted_bytes[i] ^ ord(password[i % len(password)])
        decrypted.append(chr(decrypted_char))
    change_text(output_text,''.join(decrypted))


def change_text(text_obj,changed_text):
    text_obj.delete("1.0", tk.END)
    text_obj.insert(tk.END,changed_text)

def clear_boxes():
    change_text(output_text,"")
    pw_entry.delete(0, tk.END)
    input_entry.delete(0, tk.END)


root = tk.Tk()
root.title("endecrypter v1.1")

mainframe = ttk.Frame(root, padding="3 3 7 7")
mainframe.grid(column=0, row=0)
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

inputvar = tk.StringVar()
pwvar = tk.StringVar()

a1_label = tk.Label(mainframe, text="insert the hex or the plain text")
a1_label.grid(column=1, row=1)
a2_label = tk.Label(mainframe, text="insert the password")
a2_label.grid(column=1, row=2)

input_entry = ttk.Entry(mainframe, width=40, textvariable=inputvar)
input_entry.grid(column=2, row=1)

pw_entry = ttk.Entry(mainframe, width=40, textvariable=pwvar)
pw_entry.grid(column=2, row=2)

outputvar = tk.StringVar()
output_text = tk.Text(mainframe, wrap=tk.WORD, height=5, width=50)
output_text.grid(column=1, row=4, columnspan=3)


ttk.Button(mainframe, text="Decrypt", command=lambda: decrypt(bytes.fromhex(inputvar.get()), pwvar.get())).grid(column=2, row=3)
ttk.Button(mainframe, text="Encrypt", command=lambda: encrypt(inputvar.get(), pwvar.get())).grid(column=1, row=3)
ttk.Button(mainframe, text="Clear", command=lambda: clear_boxes()).grid(column=1, row=5,columnspan=2)

root.mainloop()


