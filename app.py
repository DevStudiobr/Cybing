import requests
import dns.resolver
import whois
from bs4 import BeautifulSoup
import ssl
import socket
from wappalyzer import Wappalyzer, WebPage

def verificar_ssl(url):
    try:
        contexto = ssl.create_default_context()
        conexao = contexto.wrap_socket(socket.socket(), server_hostname=url)
        conexao.connect((url, 443))
        cert = conexao.getpeercert()
        print(f'✔ Certificado SSL válido para {url}')
    except Exception as e:
        print(f'✖ Erro ao verificar SSL: {e}')

def coletar_informacoes_dns(domino):
    try:
        # Registros A
        registros_a = dns.resolver.resolve(domino, 'A')
        print(f'\nRegistros A:')
        for registro in registros_a:
            print(f'   - {registro}')

        # Registros MX
        registros_mx = dns.resolver.resolve(domino, 'MX')
        print(f'\nRegistros MX:')
        for registro in registros_mx:
            print(f'   - {registro}')

    except Exception as e:
        print(f'✖ Erro ao coletar informações DNS: {e}')

def obter_whois(domino):
    try:
        info = whois.whois(domino)
        print(f'\nInformações WHOIS para {domino}:')
        print(f'   - Domínio: {info.domain_name}')
        print(f'   - Proprietário: {info.name}')
        print(f'   - E-mail: {info.email}')
    except Exception as e:
        print(f'✖ Erro ao obter informações WHOIS: {e}')

def detectar_tecnologias(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        tecnologias = wappalyzer.analyze(webpage)
        
        print(f'\nTecnologias encontradas em {url}:')
        for tecnologia in tecnologias:
            print(f'   - {tecnologia}')
    except Exception as e:
        print(f'✖ Erro ao detectar tecnologias: {e}')

def coletar_links(url):
    try:
        resposta = requests.get(url)
        sopa = BeautifulSoup(resposta.text, 'html.parser')
        
        links = sopa.find_all('a')
        print(f'\nLinks encontrados em {url}:')
        for link in links:
            href = link.get('href')
            print(f'   - {href}')
    except Exception as e:
        print(f'✖ Erro ao coletar links: {e}')

def exibir_menu():
    print("\n=== Menu de Informações do Site ===")
    print("1. Verificar SSL")
    print("2. Coletar informações DNS")
    print("3. Obter informações WHOIS")
    print("4. Detectar tecnologias usadas")
    print("5. Coletar links do site")
    print("6. Sair")

def main():
    url = input("Digite a URL do site (ex: http://example.com): ")
    
    # Remover "http://" ou "https://" se estiver presente
    url_sem_http = url.replace("http://", "").replace("https://", "")
    
    while True:
        exibir_menu()
        opcao = input("Escolha uma opção (1-6): ")

        if opcao == '1':
            verificar_ssl(url_sem_http)
        elif opcao == '2':
            coletar_informacoes_dns(url_sem_http)
        elif opcao == '3':
            obter_whois(url_sem_http)
        elif opcao == '4':
            detectar_tecnologias(url)
        elif opcao == '5':
            coletar_links(url)
        elif opcao == '6':
            print("Saindo do programa...")
            break
        else:
            print("✖ Opção inválida! Tente novamente.")

if __name__ == "__main__":
    main()
