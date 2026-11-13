# 🌐 PyPortScanner

![Python Version](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Conclu%C3%ADdo-success?style=for-the-badge)

O **PyPortScanner** é um scanner de rede TCP rápido, assíncrono e híbrido desenvolvido inteiramente com a biblioteca padrão do Python (Zero-Dependencies). Projetado para analistas de segurança e administradores de sistemas, ele identifica portas abertas, serviços em execução e extrai banners de servidores (Banner Grabbing) operando através de um motor multithread eficiente.

## 🚀 Funcionalidades (Features)

*   **Modo Híbrido (CLI & Interativo):** Pode ser executado de forma totalmente silenciosa via argumentos de linha de comando (ideal para automação) ou através de um assistente interativo colorido no terminal.
*   **Zero Dependências:** Funciona perfeitamente em Windows, Linux e macOS utilizando apenas recursos nativos do Python (`socket`, `concurrent.futures`, `argparse`).
*   **Banner Grabbing Ativo e Passivo:** Escuta passivamente por assinaturas de serviços (SSH, FTP) e injeta requisições ativas (*HTTP Probing*) para forçar a identificação de servidores web mascarados.
*   **Resolução Inteligente de DNS:** Suporta tanto endereços IP diretos quanto URLs completas, filtrando caminhos HTTP e resolvendo o domínio no momento do scan.
*   **Motor Multithreaded:** Varreduras altamente paralelizadas baseadas em `ThreadPoolExecutor`, garantindo alta velocidade de testes TCP Connect (`syn-ack`).
*   **Output Tabular Ordenado:** Relatório de inteligência estruturado em colunas alinhadas (`PORT`, `STATE`, `SERVICE`, `REASON`, `BANNER`).

## ⚙️ Instalação

Como o projeto não requer bibliotecas externas, o processo de execução é imediato (Drop-and-Run):

```bash
# Clone o repositório
git clone [https://github.com/Wiltonarcelino/PyPortScanner.git](https://github.com/Wiltonarcelino/PyPortScanner.git)

# Entre no diretório
cd PyPortScanner/src

# Execute a ferramenta
python scanner.py