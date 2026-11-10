import socket
import argparse

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
 

if __name__ == "__main__":
    # Criar manus no terminal
    parser = argparse.ArgumentParser(description="PyPortScanner - Scanner de portas TCP de Reconhecimento")

    # Definindo as flags (parâmetros) que o script vai receber
    parser.add_argument("-t", "--target", required=True, help="Endereço IP alvo (ex: 192.168.1.1)")
    parser.add_argument("-p", "--port", required=True, type=int, help="Porta para testar (ex: 80)")

    # Lê o que foi passado no terminal
    args = parser.parse_args()

    print(f"[*] Iniciando o scanner no IP {args.target}...\n")

    # Chamando a função scan repassando o que veio do terminal
    scan_ports(args.target, args.port)