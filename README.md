# NET-SCAN LAB: Laboratório de Varredura Ativa, Enumeração e Análise de Tráfego
### Engenharia de Reconhecimento Ofensivo, Dissecação de Protocolos e Auditoria de Superfície

---

## 1. Visão Geral do Laboratório
Este laboratório é um ambiente pedagógico, **totalmente autocontido e local**, desenvolvido para auxiliar estudantes e profissionais de segurança ofensiva no domínio prático das técnicas de varredura (camadas L3 e L4), enumeração de diretórios (camada L7) e análise forense de pacotes no fio.

O projeto sobe um painel interativo (dashboard web) na porta `80` (ou `8080` caso não executado como root) e implementa um sistema de CTF (Capture The Flag) gamificado com desafios progressivos. O laboratório roda um **IDS (Sistema de Detecção de Intrusão)** local que snifa o tráfego do loopback em tempo real, fornecendo feedback imediato de como suas varreduras e pacotes customizados estão se comportando no fio!

```
                    [ FLUXO DE FUNCIONAMENTO DO LAB ]
 
      +------------------ Atacante (Kali Linux Local) ------------------+
      |                                                                |
      |   1. nmap -sS          2. nc banner grab        3. ffuf fuzz   |
      +----------------------------------------------------------------+
                               |
                               | (Tráfego Loopback lo - 127.0.0.1)
                               v
      +-------------------- Host de Destino (Lab) --------------------+
      |                                                                |
      |   [Porta 80/8080]      [Porta 9001]            [IDS Sniffer]   |
      |   Site/Dashboard       Mock FTP Server         Raw Socket TCP  |
      |   e APIs de Fuzzing    (Banner Grab Flag)      (Live Console)  |
      +----------------------------------------------------------------+
```

---

## 2. Requisitos e Pré-requisitos
O laboratório foi desenhado para rodar nativamente no **Kali Linux**, mas pode ser executado em qualquer distribuição Linux de sua preferência.

### Instalação de Dependências Rápidas (no Kali):
```bash
sudo apt update && sudo apt install -y nmap wireshark ffuf hping3 netcat-traditional seclists python3
```

---

## 3. Como Executar o Laboratório
Para iniciar o laboratório, clone este diretório em sua máquina de trabalho, entre na pasta e execute o script de automação:

```bash
# 1. Torne o script executável
chmod +x start.sh

# 2. Inicialize o laboratório (recomendado usar sudo para privilégios de Raw Socket e Porta 80)
sudo ./start.sh
```

Após a inicialização, abra seu navegador web e acesse:
👉 **[http://localhost/](http://localhost/)** (se executado como root/sudo)  
👉 **[http://localhost:8080/](http://localhost:8080/)** (se executado como usuário comum)

---

## 4. Roteiro dos Desafios (CTF)

O laboratório possui **5 Desafios Progressivos** que devem ser resolvidos na ordem. À medida que você submete a Flag correta, o desafio seguinte é desbloqueado no painel.

### 🏁 Desafio 1: Mapeando Portas Ocultas (Nmap)
* **Objetivo:** Encontrar a porta TCP oculta configurada acima de 9000 no localhost.
* **Comando sugerido:**
  ```bash
  nmap -p 9000-9500 127.0.0.1
  ```
* **Missão:** Responder com o número da porta aberta identificada.

### 🏁 Desafio 2: Extração de Banners (Banner Grabbing)
* **Objetivo:** Capturar a mensagem de boas-vindas do serviço na porta descoberta no Desafio 1 para extrair a Flag.
* **Comando sugerido:**
  ```bash
  nc -vn 127.0.0.1 [PORTA_DESCOBERTA]
  ```
* **Missão:** Encontrar a flag no formato `FLAG{...}` contida no preâmbulo do protocolo.

### 🏁 Desafio 3: Análise de Estados no Wireshark
* **Objetivo:** Capturar e identificar a diferença visual no fio entre um escaneamento Connect (`-sT`) e um Stealth SYN Scan (`-sS`).
* **Instruções:** Abra o Wireshark, selecione a interface `lo` (loopback) e filtre por `tcp.port == 9001`. Execute as duas varreduras abaixo e compare a pilha de pacotes:
  ```bash
  # Varredura Completa
  nmap -sT -p 9001 127.0.0.1
  
  # Varredura Semi-Aberta (Stealth)
  sudo nmap -sS -p 9001 127.0.0.1
  ```
* **Missão:** Identificar a flag de 3 letras que o atacante envia para o alvo no scan `-sS` para abortar a conexão logo após receber o `SYN-ACK`.

### 🏁 Desafio 4: Fuzzing Assíncrono com ffuf
* **Objetivo:** Mapear diretórios e arquivos de configuração ocultos na porta web do laboratório (80 ou 8080) usando fuzzing L7.
* **Comando sugerido (ajuste a porta para 8080 se rodar sem sudo):**
  ```bash
  ffuf -u http://127.0.0.1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .json,.sql -mc 200,301 -c
  ```
* **Missão:** Fazer o download do arquivo de backup `.sql` exposto identificado e inserir a flag contida nas queries SQL.

### 🏁 Desafio 5: Mapeamento de Regras de Firewall com Hping3
* **Objetivo:** Compreender a utilidade prática do TCP ACK Scan para detectar se um firewall realiza filtragem com ou sem estado (Stateful vs Stateless).
* **Comando sugerido:**
  ```bash
  sudo hping3 -A -p 80 127.0.0.1 -c 3
  ```
* **Missão:** Observar o tráfego de resposta gerado no console do IDS (ou no Wireshark) e responder qual flag TCP o kernel retorna ao receber um `ACK` arbitrário em uma porta aberta/fechada não filtrada.

---

## 5. Teoria Avançada de Transporte L4
Abaixo está a matriz base de comportamento de estados de portas regulamentada pela **RFC 793** e **RFC 9293**, útil para responder às questões e auditar infraestruturas externas:

| Estado da Porta | Resposta Observada no Fio |
| :--- | :--- |
| **Open (Aberta)** | TCP `[SYN, ACK]` |
| **Closed (Fechada)** | TCP `[RST, ACK]` |
| **Filtered (Filtrada)** | Ausência de resposta (Timeout) ou ICMP erro (Type 3 Code 1, 2, 3, 9, 10 ou 13) |

### Varreduras Inversas (FIN, Xmas, NULL):
Probes sem flags de handshake ativas (ex: `nmap -sX` ou `nmap -sN`) exploram uma brecha da RFC 793. Hosts baseados em Linux/Unix ignoram o pacote se a porta estiver aberta, resultando em ausência de resposta (`open|filtered`). Se a porta estiver fechada, respondem com `[RST, ACK]`. Pilhas TCP de sistemas Microsoft Windows não cumprem a especificação RFC à risca e respondem `[RST]` a qualquer probe invertido, tornando esses scans ineficazes contra Windows de forma direta.

---

## 6. Governança Forense e Regras de Engajamento
1. **Art. 154-A do Código Penal:** A simples varredura de portas não configura violação ilegal, contudo a exploração ativa de falhas, injeções de pacotes destrutivos ou testes de senhas por brute force configuram conduta típica tipificada.
2. **LGPD (Lei 13.709/2018):** A coleta de banners que identifiquem dados corporativos sensíveis ou IPs internos de funcionários entra na governança de proteção de dados e necessita de consentimento documentado em RoE (Rules of Engagement).

---

## 👥 7. Autoria e Contato
Este projeto foi desenvolvido pelo professor **Guilherme Legal de Oliveira** como ferramenta de ensino para laboratórios de redes e segurança defensiva/ofensiva.

* **E-mail Institucional:** [gloliveira@furb.br](mailto:gloliveira@furb.br)
* **LinkedIn:** [Prof. Guilherme Legal de Oliveira](https://www.linkedin.com/in/guilherme-legal-de-oliveira-9b76735a/)

