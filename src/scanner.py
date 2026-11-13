import socket
import argparse
import concurrent.futures
import sys
import time
import os

def scan_ports(ip, port):
    # Especificar o endereço IP e a o protocolo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Defini um tempo limite para a conexão
    sock.settimeout(1)

    # Tenta se conectar a porta especificada 
    resultado = sock.connect_ex((ip, port))

    dados_porta = None

    if resultado == 0:
        try:
            servico = socket.getservbyport(port, "tcp").lower()
        except:
            servico = "Unknown"
    # A CORREÇÃO ESTÁ AQUI: Declarar a variável antes do try garante que ela sempre exista
        banner_limpo = ""
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
                
        except:
            # Falhas de timeout ou recusa silenciosa de conexão são ignoradas para não travar o scanner
            pass 
        # --- FIM DO BANNER GRABBING ---

        dados_porta = {
            "porta": port,
            "status": "Open",
            "servico": servico,
            "reason": "syn-ack",
            "banner": banner_limpo[:50]
        }

    sock.close()
    return dados_porta

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

# MOTOR CENTRAL: Roda as threads e imprime a tabela centralizada
def executar_scanner(dominio_alvo, ip_alvo, port_range, workers):
    print(f"\nStarting PyPortScanner on {dominio_alvo} ({ip_alvo})")
    start_time = time.time()
    resultados_abertos = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_ports, ip_alvo, porta) for porta in port_range]

        for future in concurrent.futures.as_completed(futures):
            resultado = future.result()
            if resultado:
                resultados_abertos.append(resultado)

    resultados_abertos.sort(key=lambda x: x["porta"])

    print(f"\n[>] Results for {dominio_alvo}:")
    print(f"    {'PORT':<7} {'STATE':<7} {'SERVICE':<12} {'REASON':<10} BANNER")
    
    for r in resultados_abertos:
        print(f"    {r['porta']:<7} {r['status']:<7} {r['servico']:<12} {r['reason']:<10} {r['banner']}")

    tempo_total = round(time.time() - start_time, 2)
    quantidade_portas = len(port_range)
    print(f"\nAsync TCP Connect scan of {quantidade_portas} ports for {dominio_alvo} completed in {tempo_total} seconds\n")

# MODO INTERATIVO (Menu)
def menu_interativo():
    print("\n--- PyPortScanner Interactive Mode ---")
    
    alvo_input = input("[?] Digite o IP ou URL alvo: ").strip()
    if not alvo_input:
        print("[!] Alvo inválido. Saindo...")
        sys.exit(1)
        
    dominio_alvo, ip_alvo = resolve_target(alvo_input)
    
    print("\nModos de Varredura:")
    print(" [1] Rápido (1-1024)")
    print(" [2] Completo (1-65535)")
    print(" [3] Customizado (ex: 80 ou 20-100)")
    
    opcao = input("[?] Escolha o modo [1]: ").strip()
    
    if opcao == "2":
        port_range = range(1, 65536)
    elif opcao == "3":
        port_str = input("[?] Digite o range de portas: ").strip()
        port_range = parse_port_range(port_str)
    else:
        port_range = range(1, 1025)

    workers_input = input("\n[?] Número de threads [50]: ").strip()
    workers = int(workers_input) if workers_input.isdigit() else 50
    
    # Chama o motor central
    executar_scanner(dominio_alvo, ip_alvo, port_range, workers)

if __name__ == "__main__":
    # Se o usuário digitou só "python scanner.py" (len == 1), abre o menu
    if len(sys.argv) == 1:
        try:
            menu_interativo()
        except KeyboardInterrupt:
            print("\n[!] Saindo...")
            sys.exit(0)
    
    # Se o usuário digitou argumentos (ex: -t 1.1.1.1), vai direto para o modo CLI
    else:
        parser = argparse.ArgumentParser(description="PyPortScanner - Scanner de Redes")
        # required=False para permitir que o script rode sem argumentos no modo interativo
        parser.add_argument("-t", "--target", required=False, help="Endereço IP alvo (ex: 192.168.1.1)")
        parser.add_argument("-w", "--workers", type=int, default=50, help="Número de threads simultâneas (default: 50)")
        parser.add_argument("--all", action="store_true", help="Escaneia todas as portas (1-65535)")
        parser.add_argument("-p", "--ports", type=str, help="Range de portas a serem escaneadas (ex: 1-1024 ou 8080)")

        args = parser.parse_args()
        
        # Como o -t não é mais obrigatório no argparse, validamos ele aqui
        if not args.target:
            print("[!] Erro: O argumento -t/--target é obrigatório no modo direto.")
            sys.exit(1)

        dominio_alvo, ip_alvo = resolve_target(args.target)

        if args.ports:
            port_range = parse_port_range(args.ports)
        elif args.all:
            port_range = range(1, 65536)
        else:
            port_range = range(1, 1025)

        # Chama o motor central
        executar_scanner(dominio_alvo, ip_alvo, port_range, args.workers)