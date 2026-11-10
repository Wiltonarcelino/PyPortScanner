import socket
import argparse
import concurrent.futures

def scan_ports(ip, port):
    # Especificar o endereço IP e a o protocolo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Defini um tempo limite para a conexão
    sock.settimeout(0.5)

    # Tenta se conectar a porta especificada 
    resultado = sock.connect_ex((ip, port))

    if resultado == 0:
        try:
            servico = socket.getservbyport(port, "tcp").upper()
        except:
            servico = "Serviço desconhecido"

        print(f"[+] A porta {port}/TCP ABERTA \t Serviço: {servico}")

    sock.close()
 

if __name__ == "__main__":
    # Criar manus no terminal
    parser = argparse.ArgumentParser(description="PyPortScanner - Scanner de Redes")

    # Definindo as flags (parâmetros) que o script vai receber
    parser.add_argument("-t", "--target", required=True, help="Endereço IP alvo (ex: 192.168.1.1)")

    # Lê o que foi passado no terminal
    args = parser.parse_args()
    ip_alvo = args.target

    print(f"[*] Iniciando o scanner no IP {args.target} (Aguarde...)\n")

    # Range de portas a serem escaneadas
    port_range = range(1, 1025)
    # Cria trabalhos pararelos pra testar as portas simultanealmente
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for porta in port_range:
            executor.submit(scan_ports, ip_alvo, porta)

    print ("\n[*] escaner finalizado!")