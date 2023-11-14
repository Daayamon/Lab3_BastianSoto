import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import random

def diffie_hellman(p, g):
    # Generar aleatoriamente las claves privadas 'a' y 'b' para el intercambio de claves Diffie-Hellman
    a = random.randint(1, 100)
    b = random.randint(1, 100)
    
    # Calcular las claves públicas 'A' y 'B' usando el intercambio de claves Diffie-Hellman
    A = ((pow(g, a)) % p)
    B = ((pow(g, b)) % p)
    
    # Calcular las claves compartidas 'Ka' y 'Kb' utilizando las claves públicas recibidas
    Ka = ((pow(B, a)) % p)
    Kb = ((pow(A, b)) % p)
    
    return Ka, Kb

def des_encrypt(key, data):
    # Crear un objeto de cifrado DES en modo ECB con la clave proporcionada
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Asegurarse de que los datos estén en formato utf-8 y realizar el relleno necesario
    if not data:
        data = ' '  # o cualquier valor predeterminado no vacío
    padded_data = pad(data.encode('utf-8'), DES.block_size)
    
    # Encriptar los datos
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

def des_decrypt(key, encrypted_data):
    # Crear un objeto de cifrado DES en modo ECB con la clave proporcionada
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Desencriptar los datos
    decrypted_data = cipher.decrypt(encrypted_data)
    
    try:
        # Quitar el relleno y decodificar los datos en utf-8
        unpadded_data = unpad(decrypted_data, DES.block_size)
        return unpadded_data.decode('utf-8')
    except ValueError as e:
        # Manejar el error si ocurre al quitar el relleno
        print("Error al quitar el relleno:", e)
        print("Mensaje cifrado original:", encrypted_data)
        print("Longitud del mensaje cifrado original:", len(encrypted_data))
        return None

def main():
    # Configurar el servidor
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 12345))
    server.listen(1)
    print("Esperando conexión...")
    conn, addr = server.accept()
    print("Conectado a", addr)

    # Intercambio de claves Diffie-Hellman
    p = 13
    g = 5
    Ka, Kb = diffie_hellman(p, g)

    # Enviar la clave pública 'Ka' al cliente
    conn.sendall(str(Ka).encode())
    
    # Recibir la clave pública 'Kb' del cliente
    Kb_received = int(conn.recv(1024).decode())

    print("Clave compartida:", Ka)

    # Clave para DES
    des_key = str(Kb_received).zfill(8).encode()
    print("Clave DES generada:", des_key)

    # Recibir el mensaje cifrado del cliente
    encrypted_message_des = conn.recv(1024)
    print("Mensaje cifrado recibido del cliente:", encrypted_message_des)

    # Desencriptar el mensaje con DES
    decrypted_message_des = des_decrypt(des_key, encrypted_message_des)

    # Imprimir el mensaje desencriptado
    print("Mensaje DES desencriptado:", decrypted_message_des)

    # Escribir el mensaje desencriptado en un archivo
    with open("mensajerecibido_des.txt", "w+") as file:
        file.write(decrypted_message_des)

    # Cerrar la conexión
    conn.close()

if __name__ == "__main__":
    main()
