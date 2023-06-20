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
