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
    # Configurar el cliente y conectarse al servidor
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 12345))

    # Intercambio de claves Diffie-Hellman
    p = int(input("Ingrese p: "))
    g = int(input("Ingrese g: "))
    Ka, Kb = diffie_hellman(p, g)

    # Enviar la clave pública 'Kb' al servidor
    client.sendall(str(Kb).encode())
    
    # Recibir la clave pública 'Ka' del servidor
    Ka_received = int(client.recv(1024).decode())

    print("Clave compartida recibida del servidor:", Ka_received)

    # Clave para DES
    des_key = str(Ka_received).zfill(8).encode()
    print("Clave DES generada:", des_key)

    # Leer el mensaje desde el archivo
    with open("mensajeentrada.txt", "r") as file:
        message = file.read()

    # Encriptar el mensaje con DES
    encrypted_message_des = des_encrypt(des_key, message)

    # Enviar el mensaje cifrado al servidor
    print("Mensaje cifrado enviado al servidor:", encrypted_message_des)
    client.sendall(encrypted_message_des)

    # Cerrar la conexión
    client.close()

if __name__ == "__main__":
    main()
