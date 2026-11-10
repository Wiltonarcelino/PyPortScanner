import socket

def scan_ports(ip, port):
    # Especificar o endereço IP e a o protocolo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Defini um tempo limite para a conexão
    sock.settimeout(1)

    # Tenta se conectar a porta especificada 
    resultado = sock.connect_ex((ip, port))

    if resultado == 0:
        print(f"[+] A porta {port}/TCP no IP {ip} está ABERTA")
    else:
        print(f"[-] A porta {port}/TCP no IP {ip} está FECHADA")

        sock.close()

# Teste de bancada 

if __name__ == "__main__":
    alvo = "1.1.1.1" 
    porta_teste = 53

    print(f"Escaneando a porta {porta_teste} no IP {alvo}...")
    scan_ports(alvo, porta_teste)