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
 
# NOVA FUNÇÃO: Traduz o texto do terminal em um range de portas
def parse_port_range(port_range_str):
    # separa o range de portas em duas partes (-)
    if "-" in port_range_str:
        start_port, end_port = port_range_str.split("-")
        # Se não tiver número antes do "-" assume que é a porta 1
        start_port = int(start_port) if start_port else 1
        end_port = int(end_port) if end_port else 65535
        return range(start_port, end_port + 1)
    else:
        # Se digitar apenas um número, retorna um range com apenas essa porta
        return range(int(port_range_str), int(port_range_str) + 1)

if __name__ == "__main__":
    # Criar manus no terminal
    parser = argparse.ArgumentParser(description="PyPortScanner - Scanner de Redes")

    # Definindo as flags (parâmetros) que o script vai receber
    parser.add_argument("-t", "--target", required=True, help="Endereço IP alvo (ex: 192.168.1.1)")

    # Define as flags (parâmetros) opcionais
    parser.add_argument("-w", "--workers", type=int, default=50, help= "Número de threads simultâneas (default: 50)")
    parser.add_argument("--all", action="store_true", help="Escaneia todas as portas (1-65535)")
    parser.add_argument("-p", "--ports", type=str, help="Range de portas a serem escaneadas (ex: 1-1024 ou 8080)")

    # Lê o que foi passado no terminal
    args = parser.parse_args()
    ip_alvo = args.target

    print(f"[*] Iniciando o scanner no IP {args.target} (Aguarde...)\n")

    # Range de portas a serem escaneadas
    if args.ports:
        port_range = parse_port_range(args.ports)
        print(f"[*] Iniciando scanner customizado (Portas {args.ports})")
    elif args.all:
        port_range = range(1, 65536)
        print(f"[*] Iniciando scanner completo (65.535 portas).")
    else:
        port_range = range(1, 1025)
        print(f"[*] Iniciando scanner rápido (1.024 portas)")

    print(f"[*] Usando {args.workers} threads simultâneas\n")

    # Cria trabalhos pararelos pra testar as portas simultanealmente
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for porta in port_range:
            executor.submit(scan_ports, ip_alvo, porta)

    print ("\n[*] escaner finalizado!")