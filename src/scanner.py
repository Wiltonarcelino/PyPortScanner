import socket
import argparse
import concurrent.futures
import sys

def scan_ports(ip, port):
    # Especificar o endereço IP e a o protocolo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Defini um tempo limite para a conexão
    sock.settimeout(1)

    # Tenta se conectar a porta especificada 
    resultado = sock.connect_ex((ip, port))

    if resultado == 0:
        try:
            servico = socket.getservbyport(port, "tcp").upper()
        except:
            servico = "SERVIÇO DESCONHECIDO"

# --- INÍCIO DO BANNER GRABBING ---
        banner_info = ""
        try:
            # PASSO 1: Escuta passiva (para serviços que falam primeiro, ex: SSH e FTP)
            resposta = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # PASSO 2: Escuta ativa / Probing (se o servidor for web e exigir requisição HTTP)
            if not resposta:
                cutucao_http = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PyPortScanner/1.0\r\nAccept: */*\r\n\r\n"
                sock.sendall(cutucao_http.encode('utf-8'))
                resposta = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # PASSO 3: Parseamento e formatação do Banner
            if resposta:
                banner_limpo = ""
                # Extração inteligente para cabeçalhos HTTP
                if "HTTP" in resposta.upper():
                    for linha in resposta.split('\n'):
                        if "server:" in linha.lower():
                            banner_limpo = linha.strip()
                            break
                    # Fallback: Se o servidor ocultar a tag Server, captura o Status HTTP
                    if not banner_limpo:
                        banner_limpo = resposta.split('\n')[0].strip()
                
                # Tratamento para serviços comuns (remoção de quebras de linha)
                if not banner_limpo:
                    banner_limpo = resposta.replace('\r', '').replace('\n', ' ')
                
                banner_info = f"  --->  [{banner_limpo[:80]}]"
        except:
            # Falhas de timeout ou recusa silenciosa de conexão são ignoradas para não travar o scanner
            pass 
        # --- FIM DO BANNER GRABBING ---

        print(f"[+] A porta {port}/TCP ABERTA \t Serviço: {servico}{banner_info}")

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

# NOVA FUNÇÃO: Limpa a URL para extrair apenas o endereço IP ou hostname
def resolve_target(alvo_cru):
        # 1. Limpa lixos de URL (http, https, barras no final
        alvo_limpo = alvo_cru.replace("http://", "").replace("https://", "").rstrip("/")
        alvo_limpo = alvo_limpo.split("/")[0] # Tira caminhos como /admin ou /login

        try:
            # 2. Pergunta ao DNS qual é o IP do alvo
            ip_resolvido = socket.gethostbyname(alvo_limpo)
            return alvo_limpo, ip_resolvido
        except socket.gaierror:
            # 3. Tratamendo elegante de erro caso o DNS não consiga resolver o alvo
            print(f"[!] Erro: Não foi possível resolver o alvo '{alvo_limpo}' para um endereço IP. Verifique se o endereço está correto.")
            print("[!] Verifique sua conexão com a internet ou se o endereço está correto.")
            sys.exit(1)

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

    print(f"[*] Iniciando o scanner no alvo: {args.target} (Aguarde...)\n")
    dominio_alvo, ip_alvo = resolve_target(args.target)

    # Mostramos o resultado no terminal para analista ver quem é o alvo
    if dominio_alvo != ip_alvo:
        print(f"[*] Alvo resolvido (DNS): {dominio_alvo} -> {ip_alvo}")

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