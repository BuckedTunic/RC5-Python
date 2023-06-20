import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import re

def rc5_encrypt(key, data):
    # Parámetros de RC5
    w = 32
    r = 12
    b = len(key)
    c = len(data) // 8

    # Constantes de RC5
    P = 0xB7E15163
    Q = 0x9E3779B9

    # Funciones auxiliares
    def rotate_left(val, r_bits, max_bits):
        return (val << r_bits % max_bits) & (2**max_bits - 1) | \
               ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

    # Expandir la clave
    L = [key[i:i+4] for i in range(0, b, 4)]
    L += [b'\x00\x00\x00\x00'] * ((r + 1) * 2 - len(L))
    S = [(P + (i * Q)) & (2**w - 1) for i in range((r + 1) * 2)]

    # Convertir clave a enteros
    L = [int.from_bytes(x, 'little') for x in L]

    # Procesar los datos
    encrypted_data = []
    for i in range(c):
        A = int.from_bytes(data[i*8:(i+1)*8][:4], 'little')
        B = int.from_bytes(data[i*8:(i+1)*8][4:], 'little')

        A = (A + S[0]) & (2**w - 1)
        B = (B + S[1]) & (2**w - 1)

        for j in range(1, r + 1):
            A = (rotate_left((A ^ B), B % w, w) + S[2*j]) & (2**w - 1)
            B = (rotate_left((B ^ A), A % w, w) + S[2*j + 1]) & (2**w - 1)

        A = (A + S[r + 1]) & (2**w - 1)
        B = (B + S[r + 2]) & (2**w - 1)

        encrypted_data.extend(A.to_bytes(4, 'little') + B.to_bytes(4, 'little'))

    return bytes(encrypted_data)

def rc5_decrypt(key, data):
    # Parámetros de RC5
    w = 32
    r = 12
    b = len(key)
    c = len(data) // 8

    # Constantes de RC5
    P = 0xB7E15163
    Q = 0x9E3779B9

    # Funciones auxiliares
    def rotate_right(val, r_bits, max_bits):
        return ((val & (2**max_bits - 1)) >> r_bits % max_bits) | \
               (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))

    # Expandir la clave
    L = [key[i:i+4] for i in range(0, b, 4)]
    L += [b'\x00\x00\x00\x00'] * ((r + 1) * 2 - len(L))
    S = [(P + (i * Q)) & (2**w - 1) for i in range((r + 1) * 2)]

    # Convertir clave a enteros
    L = [int.from_bytes(x, 'little') for x in L]

    # Procesar los datos
    decrypted_data = []
    for i in range(c):
        A = int.from_bytes(data[i*8:(i+1)*8][:4], 'little')
        B = int.from_bytes(data[i*8:(i+1)*8][4:], 'little')

        B = (B - S[r + 2]) & (2**w - 1)
        A = (A - S[r + 1]) & (2**w - 1)

        for j in range(r, 0, -1):
            B = (rotate_right((B - S[2*j + 1]), A % w, w) ^ A) & (2**w - 1)
            A = (rotate_right((A - S[2*j]), B % w, w) ^ B) & (2**w - 1)

        B = (B - S[1]) & (2**w - 1)
        A = (A - S[0]) & (2**w - 1)

        decrypted_data.extend(A.to_bytes(4, 'little') + B.to_bytes(4, 'little'))

    return bytes(decrypted_data)

def validate_key(key):
    # Validar la clave
    if not re.search(r'[A-Z]', key):
        return False
    if not re.search(r'[a-z]', key):
        return False
    if not re.search(r'\d', key):
        return False
    if len(key) < 8:
        return False
    if not re.search(r'[_!$\-?¡¿]', key):
        return False
    return True

def encrypt_file():
    # Obtener la clave del campo de texto
    key = key_entry.get()

    # Validar la clave
    if not validate_key(key):
        messagebox.showwarning('Error', 'La clave no cumple con los requisitos especificados.')
        return

    # Seleccionar un archivo para encriptar
    file_path = filedialog.askopenfilename()
    if file_path:
        # Leer el archivo
        with open(file_path, 'rb') as file:
            data = file.read()

        # Encriptar los datos con RC5
        encrypted_data = rc5_encrypt(key.encode('utf-8'), data)

        # Guardar los datos en un nuevo archivo encriptado
        output_path = file_path + '.encrypted'
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)

        print('Archivo encriptado y guardado como:', output_path)

def decrypt_file():
    # Obtener la clave del campo de texto
    key = key_entry.get()

    # Validar la clave
    if not validate_key(key):
        messagebox.showwarning('Error', 'La clave no cumple con los requisitos especificados.')
        return

    # Seleccionar un archivo encriptado para desencriptar
    file_path = filedialog.askopenfilename()
    if file_path:
        # Leer el archivo encriptado
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        # Desencriptar los datos con RC5
        decrypted_data = rc5_decrypt(key.encode('utf-8'), encrypted_data)

        # Obtener la ruta y el nombre del archivo original antes de ser encriptado
        original_path = file_path[:-9]  # Eliminar la extensión ".encrypted"

        # Guardar los datos desencriptados en un nuevo archivo con el formato y ubicación original
        with open(original_path, 'wb') as file:
            file.write(decrypted_data)

        print('Archivo desencriptado y guardado como:', original_path)

# Crear la ventana
window = tk.Tk()

# Etiqueta con las instrucciones
instructions = "Ingrese una clave que cumpla con los siguientes requisitos:\n\n"\
               "- Al menos una letra mayúscula\n"\
               "- Al menos una letra minúscula\n"\
               "- Al menos un número\n"\
               "- Mínimo 8 caracteres\n"\
               "- Al menos uno de los siguientes caracteres: _ ! $ - ? ¡ ¿"
instruction_label = tk.Label(window, text=instructions)
instruction_label.pack()

# Etiqueta y campo de texto para la clave
key_label = tk.Label(window, text="Clave:")
key_label.pack()

key_entry = tk.Entry(window, show="*")
key_entry.pack()

# Botón para encriptar archivo
encrypt_button = tk.Button(window, text='Encriptar archivo', command=encrypt_file)
encrypt_button.pack()

# Botón para desencriptar archivo
decrypt_button = tk.Button(window, text='Desencriptar archivo', command=decrypt_file)
decrypt_button.pack()

# Ejecutar la ventana
window.mainloop()
