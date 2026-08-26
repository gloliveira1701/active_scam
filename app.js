/* ==========================================================================
   LAB DE RECONHECIMENTO OFENSIVO & ANÁLISE DE TRÁFEGO - LOGICA JAVASCRIPT
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // --- DATASE DE 100 DESAFIOS CTF ---
    const ALL_CHALLENGES = [
    {
        "id": 1,
        "title": "Portas Ocultas",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Encontre uma porta TCP misteriosa aberta acima de 9000 no localhost (<code>127.0.0.1</code>) usando o Nmap.",
        "cmd": "nmap -p 9000-9500 127.0.0.1",
        "help": "O Nmap é o padrão da indústria para varredura de rede. A flag -p define a faixa de portas analisada.",
        "hint": "Varra a faixa entre 9000 e 9500 na interface local.",
        "category": "nmap"
    },
    {
        "id": 2,
        "title": "Parâmetro do Connect Scan",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual o parâmetro de linha de comando do Nmap para realizar um Connect Scan completo (TCP 3-Way Handshake)?",
        "cmd": "nmap --help",
        "help": "O Connect Scan utiliza a chamada de sistema do SO para fechar conexões normais (completa o aperto de mão).",
        "hint": "Procure por '-s' seguido de uma letra maiúscula para Connect.",
        "category": "nmap"
    },
    {
        "id": 3,
        "title": "SYN Stealth Scan",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do Nmap é usada para o SYN Scan (também conhecido como Stealth ou meio-aberto)?",
        "cmd": "nmap --help",
        "help": "Este scan não fecha o handshake completo, enviando RST imediatamente após receber o SYN-ACK do alvo.",
        "hint": "Geralmente é a opção padrão quando executado como root. Começa com -sS.",
        "category": "nmap"
    },
    {
        "id": 4,
        "title": "Especificando Portas Únicas",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do Nmap serve para indicar uma única porta específica (por exemplo, apenas a porta 80)?",
        "cmd": "nmap -p 80 127.0.0.1",
        "help": "O parâmetro aceita listas separadas por vírgula ou portas individuais.",
        "hint": "É a flag minúscula '-p'.",
        "category": "nmap"
    },
    {
        "id": 5,
        "title": "Varredura Total (65535 Portas)",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual atalho/flag do Nmap é usado para varrer todas as 65535 portas TCP possíveis?",
        "cmd": "nmap -p- 127.0.0.1",
        "help": "Mapear todas as portas evita que serviços rodando em portas altas/não-padrão passem despercebidos.",
        "hint": "Use o hífen logo após o parâmetro de porta. Ex: -p-.",
        "category": "nmap"
    },
    {
        "id": 6,
        "title": "Desativação de Descoberta (No-Ping)",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual parâmetro diz ao Nmap para tratar todos os hosts como online, pulando a descoberta via ping ICMP?",
        "cmd": "nmap -Pn 127.0.0.1",
        "help": "Útil quando o firewall do alvo bloqueia ping ICMP Echo Requests mas as portas estão acessíveis.",
        "hint": "O comando começa com -P e termina com uma letra minúscula indicando no-ping (n).",
        "category": "nmap"
    },
    {
        "id": 7,
        "title": "Detecção de Sistema Operacional",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual parâmetro maiúsculo ativa a detecção do Sistema Operacional (OS Fingerprinting) no Nmap?",
        "cmd": "nmap -O 127.0.0.1",
        "help": "O Nmap analisa pequenas variações na implementação da pilha TCP/IP do alvo para deduzir o OS.",
        "hint": "É uma única letra maiúscula do alfabeto que lembra 'Operating System'.",
        "category": "nmap"
    },
    {
        "id": 8,
        "title": "Detecção de Versão de Serviços",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual parâmetro é usado para interrogar as portas abertas e determinar a versão real do serviço em execução?",
        "cmd": "nmap -sV 127.0.0.1",
        "help": "Ele envia probes de aplicação após o handshake para extrair banners de boas-vindas.",
        "hint": "Combina o prefixo de scan '-s' com a letra maiúscula 'V'.",
        "category": "nmap"
    },
    {
        "id": 9,
        "title": "Timing Template: Agressivo",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual template de temporização (Timing Template) representa o modo 'Agressivo' (usado para acelerar scans)?",
        "cmd": "nmap -T4 127.0.0.1",
        "help": "O Nmap possui 6 templates de velocidade (0 a 5). O modo 4 reduz tempos de timeout e acelera a varredura.",
        "hint": "Responda com o parâmetro completo ou apenas o código (Ex: -T4).",
        "category": "nmap"
    },
    {
        "id": 10,
        "title": "Timing Template: Paranoid",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual timing template do Nmap representa o modo mais lento, usado para evitar detecções de IDS (Paranoid)?",
        "cmd": "nmap -T0 127.0.0.1",
        "help": "O modo Paranoid insere horas de intervalo entre o envio de cada probe individual.",
        "hint": "É o menor valor da escala de 0 a 5. Digite -T0.",
        "category": "nmap"
    },
    {
        "id": 11,
        "title": "Portas Padrão no Nmap",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Por padrão, se você não especificar portas, o Nmap varre quantas portas TCP mais comuns (Top Ports)?",
        "cmd": "nmap 127.0.0.1",
        "help": "O Nmap mapeia estatisticamente as portas mais comuns de acordo com pesquisas empíricas.",
        "hint": "É um número redondo de 4 dígitos. Mil portas.",
        "category": "nmap"
    },
    {
        "id": 12,
        "title": "Saída em Formato Normal",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do Nmap salva o resultado da varredura em formato de texto comum (Normal Output)?",
        "cmd": "nmap -oN output.txt 127.0.0.1",
        "help": "Salvar saídas ajuda a manter registros de auditorias para análise posterior.",
        "hint": "Combina o prefixo '-o' com a letra 'N' (Normal).",
        "category": "nmap"
    },
    {
        "id": 13,
        "title": "Saída Grepável",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag gera uma saída de resultado estruturada para manipulação fácil via comandos do terminal (grep)?",
        "cmd": "nmap -oG output.grep 127.0.0.1",
        "help": "A saída formatada em uma única linha por host facilita a filtragem rápida via awk/grep.",
        "hint": "Combina o prefixo '-o' com a letra 'G'.",
        "category": "nmap"
    },
    {
        "id": 14,
        "title": "Saída XML para Parser",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag gera a saída no formato estruturado XML, ideal para importar em bancos ou ferramentas como Zenmap?",
        "cmd": "nmap -oX output.xml 127.0.0.1",
        "help": "O XML armazena todos os detalhes de portas, serviços e latências de maneira computável.",
        "hint": "Combina o prefixo '-o' com a letra 'X'.",
        "category": "nmap"
    },
    {
        "id": 15,
        "title": "Exportação em Todos os Formatos",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual parâmetro do Nmap exporta a varredura simultaneamente em todos os três formatos principais (.nmap, .gnmap, .xml)?",
        "cmd": "nmap -oA scan_result 127.0.0.1",
        "help": "A flag salva arquivos com o nome base em todos os formatos de saída suportados.",
        "hint": "Significa 'Output All'. Responda com -oA.",
        "category": "nmap"
    },
    {
        "id": 16,
        "title": "Varredura UDP",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é a flag do Nmap utilizada para escanear portas baseadas no protocolo de transporte sem estado UDP?",
        "cmd": "sudo nmap -sU 127.0.0.1",
        "help": "Scans UDP são lentos pois contam com erros ICMP Port Unreachable para determinar portas fechadas.",
        "hint": "Combina o prefixo de scan '-s' com a letra maiúscula 'U'.",
        "category": "nmap"
    },
    {
        "id": 17,
        "title": "Estado de Porta Closed",
        "difficulty": "fácil",
        "points": 50,
        "desc": "De acordo com o Nmap, qual é o estado de uma porta que responde ativamente com RST (Reset) ao probe SYN?",
        "cmd": "",
        "help": "Uma porta fechada aceita conexões mas recusa o estabelecimento, pois não há processo ouvindo nela.",
        "hint": "Digite o termo em português: Fechada.",
        "category": "nmap"
    },
    {
        "id": 18,
        "title": "Estado de Porta Filtered",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Como o Nmap classifica uma porta quando não recebe nenhuma resposta ou recebe um erro ICMP Administrativo?",
        "cmd": "",
        "help": "Indica que um firewall ou regra de rede está descartando (dropping) os pacotes de teste.",
        "hint": "Digite o termo em português: Filtrada.",
        "category": "nmap"
    },
    {
        "id": 19,
        "title": "Probe de Descoberta Local",
        "difficulty": "médio",
        "points": 100,
        "desc": "Se executado com privilégios de root em uma rede local (LAN), qual protocolo o Nmap usa por padrão para descoberta de hosts ativos?",
        "cmd": "",
        "help": "Em redes locais, requisições de mapeamento físico (Camada 2) são muito mais rápidas que ICMP.",
        "hint": "Abreviação de Address Resolution Protocol.",
        "category": "nmap"
    },
    {
        "id": 20,
        "title": "Scripts Padrão (NSE)",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual categoria padrão de scripts do NSE (Nmap Scripting Engine) é executada quando usamos a flag '-sC'?",
        "cmd": "nmap -sC 127.0.0.1",
        "help": "Essa flag executa um conjunto de scripts seguros, rápidos e não intrusivos.",
        "hint": "Responda com o nome do grupo em inglês: default.",
        "category": "nmap"
    },
    {
        "id": 21,
        "title": "Banner Grabbing Manual",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se manualmente no serviço FTP simulado na porta 9001. Encontre a FLAG exibida no banner de boas-vindas.",
        "cmd": "nc -vn 127.0.0.1 9001",
        "help": "Serviços FTP expõem mensagens iniciais contendo informações do software e dados adicionais.",
        "hint": "Use netcat (nc) para ler a mensagem inicial do servidor na porta 9001.",
        "category": "netcat"
    },
    {
        "id": 22,
        "title": "Ferramenta de Grab Clássica",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual utilitário de terminal leve (apelidado de canivete suíço do hacker) é usado para conexões cruas TCP/UDP?",
        "cmd": "nc --help",
        "help": "Permite escutar portas, transferir arquivos e depurar soquetes de rede.",
        "hint": "Abreviação de netcat. Responda 'netcat' ou 'nc'.",
        "category": "netcat"
    },
    {
        "id": 23,
        "title": "Porta Padrão do SSH",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta padrão utilizada mundialmente pelo serviço Secure Shell (SSH)?",
        "cmd": "",
        "help": "O SSH fornece um canal seguro sobre uma rede insegura em uma arquitetura cliente-servidor.",
        "hint": "É um número inteiro menor que 25.",
        "category": "netcat"
    },
    {
        "id": 24,
        "title": "Porta Padrão do FTP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta TCP padrão de controle do serviço File Transfer Protocol (FTP)?",
        "cmd": "",
        "help": "O FTP utiliza conexões separadas de controle (porta X) e dados (porta X-1).",
        "hint": "É o número 21.",
        "category": "netcat"
    },
    {
        "id": 25,
        "title": "Porta Padrão do SMTP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta de controle usada pelo protocolo de envio de e-mails Simple Mail Transfer Protocol (SMTP)?",
        "cmd": "",
        "help": "Esse protocolo realiza a transferência de mensagens entre servidores de correio eletrônico.",
        "hint": "É o número 25.",
        "category": "netcat"
    },
    {
        "id": 26,
        "title": "Porta Padrão do DNS",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual porta padrão (TCP/UDP) é associada ao Domain Name System (DNS)?",
        "cmd": "",
        "help": "O DNS resolve nomes de domínio legíveis para humanos em endereços IP numéricos.",
        "hint": "É o número 53.",
        "category": "netcat"
    },
    {
        "id": 27,
        "title": "Porta Padrão do HTTP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta TCP padrão utilizada para conexões web comuns sem criptografia (HTTP)?",
        "cmd": "",
        "help": "O tráfego web puro trafega por essa porta clássica.",
        "hint": "É o número 80.",
        "category": "netcat"
    },
    {
        "id": 28,
        "title": "Porta Padrão do HTTPS",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta TCP padrão associada ao tráfego HTTP seguro criptografado com SSL/TLS (HTTPS)?",
        "cmd": "",
        "help": "Criptografa as comunicações web para proteger dados confidenciais.",
        "hint": "É o número 443.",
        "category": "netcat"
    },
    {
        "id": 29,
        "title": "Porta Padrão do MySQL",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta padrão mais comum para o banco de dados relacional MySQL?",
        "cmd": "",
        "help": "Saber portas de bancos de dados auxilia a identificar alvos de fuzzing de credenciais.",
        "hint": "É o número 3306.",
        "category": "netcat"
    },
    {
        "id": 30,
        "title": "Porta Padrão do RDP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a porta de escuta padrão do protocolo de acesso remoto gráfico do Windows (Remote Desktop Protocol - RDP)?",
        "cmd": "",
        "help": "O RDP permite gerenciar desktops Windows remotamente via interface gráfica.",
        "hint": "É o número 3389.",
        "category": "netcat"
    },
    {
        "id": 31,
        "title": "Segredo do SSH Banner",
        "difficulty": "médio",
        "points": 100,
        "desc": "O banner inicial exibido ao conectar manualmente na porta SSH de um servidor normalmente revela qual informação importante?",
        "cmd": "",
        "help": "Muitos administradores não removem esses dados, permitindo que atacantes descubram falhas associadas à build específica do software.",
        "hint": "Indica a 'Versão' do software/sistema operacional rodando.",
        "category": "netcat"
    },
    {
        "id": 32,
        "title": "Intensidade de Mapeamento de Versão",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual parâmetro do Nmap controla o nível de agressividade da detecção de serviços (valores de 0 a 9)?",
        "cmd": "nmap --help",
        "help": "Valores mais altos testam assinaturas raras, enquanto valores baixos apenas executam probes comuns.",
        "hint": "Parâmetro completo: '--version-intensity'.",
        "category": "nmap"
    },
    {
        "id": 33,
        "title": "Linguagem dos Scripts Nmap",
        "difficulty": "médio",
        "points": 100,
        "desc": "Os scripts customizados que rodam no Nmap (extensão .nse) são escritos em qual linguagem de programação?",
        "cmd": "",
        "help": "Uma linguagem de script embutível, rápida e extremamente leve desenvolvida na PUC-Rio.",
        "hint": "É a linguagem brasileira: Lua.",
        "category": "nmap"
    },
    {
        "id": 34,
        "title": "Sigla do Motor de Scripts",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é a sigla em inglês para o motor de execução de scripts de automação do Nmap?",
        "cmd": "",
        "help": "Significa Nmap Scripting Engine.",
        "hint": "Três letras maiúsculas: NSE.",
        "category": "nmap"
    },
    {
        "id": 35,
        "title": "Categoria de Vulnerabilidades NSE",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual categoria de scripts do NSE serve especificamente para detectar vulnerabilidades conhecidas no alvo?",
        "cmd": "nmap --script-help vuln",
        "help": "O NSE agrupa scripts em categorias como default, auth, vuln, safe e malware.",
        "hint": "Abreviação em inglês para vulnerabilidades: 'vuln'.",
        "category": "nmap"
    },
    {
        "id": 36,
        "title": "Categoria de Autenticação NSE",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual categoria de scripts do NSE serve para testar senhas padrão ou realizar força bruta básica no alvo?",
        "cmd": "",
        "help": "Essa categoria engloba scripts que lidam com login e credenciais.",
        "hint": "Abreviação em inglês para autenticação: 'auth'.",
        "category": "nmap"
    },
    {
        "id": 37,
        "title": "Flag para Chamar Scripts",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag do Nmap permite que você declare especificamente qual arquivo ou diretório de scripts NSE rodar?",
        "cmd": "nmap --script=banner 127.0.0.1",
        "help": "Permite carregar scripts isoladamente para não sobrecarregar a rede com análises desnecessárias.",
        "hint": "É o parâmetro '--script'.",
        "category": "nmap"
    },
    {
        "id": 38,
        "title": "Diretório NSE no Linux",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual é o diretório absoluto padrão em sistemas Linux (Kali) onde ficam armazenados os arquivos de scripts .nse?",
        "cmd": "",
        "help": "Você pode navegar para essa pasta para estudar os códigos-fonte dos scripts ou adicionar novos.",
        "hint": "Começa com '/usr/share/nmap/scripts'.",
        "category": "nmap"
    },
    {
        "id": 39,
        "title": "Atualizando a Base do NSE",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual comando ou argumento do Nmap atualiza o banco de dados interno de referências a scripts NSE?",
        "cmd": "sudo nmap --script-updatedb",
        "help": "Necessário após instalar ou modificar scripts customizados.",
        "hint": "O argumento completo é '--script-updatedb'.",
        "category": "nmap"
    },
    {
        "id": 40,
        "title": "Código de Sucesso SMTP",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Ao se conectar manualmente a um serviço SMTP, qual código numérico de 3 dígitos inicia o banner de boas-vindas?",
        "cmd": "",
        "help": "Esse status indica que o canal de transmissão está pronto para comunicação.",
        "hint": "É o código 220.",
        "category": "netcat"
    },
    {
        "id": 41,
        "title": "Flag TCP FIN",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do cabeçalho TCP (sigla de 3 letras) sinaliza o encerramento ordenado de uma conexão?",
        "cmd": "",
        "help": "Usada na finalização do handshake de desconexão (FIN-ACK).",
        "hint": "FIN.",
        "category": "wireshark"
    },
    {
        "id": 42,
        "title": "Flag TCP SYN",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do cabeçalho TCP (sigla de 3 letras) inicia a sincronização e abertura da conexão?",
        "cmd": "",
        "help": "É o primeiro pacote enviado em qualquer conexão TCP ativa.",
        "hint": "SYN.",
        "category": "wireshark"
    },
    {
        "id": 43,
        "title": "Flag TCP ACK",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag TCP (sigla de 3 letras) é usada para confirmar o recebimento de dados?",
        "cmd": "",
        "help": "Pacotes de confirmação contêm o número de sequência que o host espera a seguir.",
        "hint": "ACK.",
        "category": "wireshark"
    },
    {
        "id": 44,
        "title": "Flag TCP RST",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag TCP (sigla de 3 letras) aborta imediatamente uma conexão e reseta o canal?",
        "cmd": "",
        "help": "Enviado quando o cliente deseja cancelar o handshake ou quando a porta está fechada.",
        "hint": "RST.",
        "category": "wireshark"
    },
    {
        "id": 45,
        "title": "Flag TCP PSH",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag TCP (sigla de 3 letras) força o envio imediato de dados do buffer para a camada de aplicação?",
        "cmd": "",
        "help": "Sinaliza que o receptor não precisa esperar encher o buffer antes de repassar os dados recebidos.",
        "hint": "PSH.",
        "category": "wireshark"
    },
    {
        "id": 46,
        "title": "Flag TCP URG",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag TCP indica que o pacote possui dados urgentes apontados pelo campo ponteiro de urgência?",
        "cmd": "",
        "help": "Diz ao receptor para processar prioritariamente as informações apontadas.",
        "hint": "URG.",
        "category": "wireshark"
    },
    {
        "id": 47,
        "title": "O Segundo Passo do Handshake",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Quais duas flags combinadas (separadas por hífen ou vírgula) o alvo envia no segundo passo do 3-Way Handshake?",
        "cmd": "",
        "help": "Este pacote confirma a intenção do cliente e solicita a sua sincronização recíproca.",
        "hint": "SYN-ACK.",
        "category": "wireshark"
    },
    {
        "id": 48,
        "title": "Filtro de Porta no Wireshark",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual string de filtro do Wireshark exibe apenas pacotes TCP associados à porta 9001?",
        "cmd": "",
        "help": "Os filtros do Wireshark usam sintaxe orientada a objetos para dissecar pacotes.",
        "hint": "Sintaxe: 'tcp.port == 9001'.",
        "category": "wireshark"
    },
    {
        "id": 49,
        "title": "Filtro SYN Exclusivo",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual filtro do Wireshark seleciona pacotes onde a flag SYN está ligada (1) e a flag ACK está desligada (0)?",
        "cmd": "",
        "help": "Excelente para isolar o pacote inicial de novas tentativas de conexão.",
        "hint": "Use 'tcp.flags.syn == 1 and tcp.flags.ack == 0'.",
        "category": "wireshark"
    },
    {
        "id": 50,
        "title": "Resposta a Portas Fechadas",
        "difficulty": "médio",
        "points": 100,
        "desc": "De acordo com a RFC 793, qual pacote/flag o kernel do alvo retorna se receber um SYN direcionado a uma porta fechada?",
        "cmd": "",
        "help": "Isso informa ao emissor que não há listener ativo, abortando a conexão.",
        "hint": "RST ou RST,ACK.",
        "category": "wireshark"
    },
    {
        "id": 51,
        "title": "Hexadecimal do Xmas Scan",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual é o valor hexadecimal (ex: 0x29) ou decimal (41) associado à combinação de flags ativadas no Xmas Scan?",
        "cmd": "",
        "help": "FIN (0x01) + PSH (0x08) + URG (0x20) = 0x29 (41 em decimal).",
        "hint": "Escreva em formato hexadecimal: 0x29.",
        "category": "wireshark"
    },
    {
        "id": 52,
        "title": "Silêncio do NULL Scan",
        "difficulty": "médio",
        "points": 100,
        "desc": "O que o host alvo envia de volta em resposta a um NULL Scan se a porta investigada estiver aberta (regra RFC 793)?",
        "cmd": "",
        "help": "Sistemas em conformidade com a RFC descartam silenciosamente pacotes nulos em portas abertas.",
        "hint": "Escreva 'Nada' ou 'Nenhuma'.",
        "category": "wireshark"
    },
    {
        "id": 53,
        "title": "NULL Scan contra Porta Fechada",
        "difficulty": "médio",
        "points": 100,
        "desc": "Se a porta estiver fechada, qual pacote de retorno o alvo envia para um NULL scan (RFC 793)?",
        "cmd": "",
        "help": "Portas fechadas respondem ativamente com RST para pacotes inesperados.",
        "hint": "RST.",
        "category": "wireshark"
    },
    {
        "id": 54,
        "title": "RFC Histórica do TCP",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é a RFC original do ano de 1981 que define o padrão inicial do protocolo de controle de transmissão (TCP)?",
        "cmd": "",
        "help": "É o pilar fundamental que documentou como a internet estruturou suas conexões por décadas.",
        "hint": "Escreva no formato: RFC 793.",
        "category": "wireshark"
    },
    {
        "id": 55,
        "title": "RFC Moderna do TCP",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual é a RFC atualizada de 2022 que consolidou e substituiu a RFC antiga do TCP?",
        "cmd": "",
        "help": "Ela reuniu dezenas de erratas e revisou o algoritmo de handshake e encerramento.",
        "hint": "Escreva no formato: RFC 9293.",
        "category": "wireshark"
    },
    {
        "id": 56,
        "title": "Filtro Wireshark de IP Origem",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual o filtro do Wireshark para isolar pacotes vindo de um IP de origem específico (ip.src)?",
        "cmd": "",
        "help": "Filtra o fluxo apenas pela máquina que originou o tráfego.",
        "hint": "Use 'ip.src'.",
        "category": "wireshark"
    },
    {
        "id": 57,
        "title": "Filtro de Métodos HTTP POST",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é o filtro do Wireshark para listar apenas requisições HTTP do tipo POST?",
        "cmd": "",
        "help": "Permite encontrar locais de envio de dados e formulários.",
        "hint": "Use 'http.request.method == \"POST\"'.",
        "category": "wireshark"
    },
    {
        "id": 58,
        "title": "Transporte sem Handshake",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual protocolo da camada de transporte (L4) não possui handshake e envia pacotes sem estado?",
        "cmd": "",
        "help": "É rápido mas não garante a entrega ordenada de dados.",
        "hint": "Três letras em maiúsculo: UDP.",
        "category": "wireshark"
    },
    {
        "id": 59,
        "title": "Erro ICMP UDP Fechado",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual código de erro ICMP indica que uma porta UDP varrida está de fato fechada?",
        "cmd": "",
        "help": "O kernel responde informando que a porta está inacessível.",
        "hint": "Escreva 'Port Unreachable' ou 'Type 3 Code 3'.",
        "category": "wireshark"
    },
    {
        "id": 60,
        "title": "Wireshark em Linha de Comando",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual ferramenta clássica em linha de comando serve como versão CLI do Wireshark?",
        "cmd": "tshark -i lo",
        "help": "Excelente para interceptação rápida em servidores headless sem interface gráfica.",
        "hint": "tshark.",
        "category": "wireshark"
    },
    {
        "id": 61,
        "title": "Bypass via Xmas Scan",
        "difficulty": "médio",
        "points": 100,
        "desc": "Ative o Firewall no menu lateral. A varredura SYN padrão falhará. Execute um Xmas Scan e pegue a FLAG no log do IDS.",
        "cmd": "sudo nmap -sX 127.0.0.1 -p 9001",
        "help": "Xmas define FIN, PSH e URG. Firewalls sem estado (stateless) apenas bloqueiam pacotes SYN de entrada.",
        "hint": "Monitore a aba IDS Console após executar o comando.",
        "category": "wireshark"
    },
    {
        "id": 62,
        "title": "Bypass via ACK Scan",
        "difficulty": "médio",
        "points": 100,
        "desc": "Com o Firewall ativo, faça um probe de ACK via Hping3 e pegue a FLAG que o firewall libera no log do IDS.",
        "cmd": "sudo hping3 -A -p 9001 127.0.0.1 -c 3",
        "help": "O tráfego ACK simula uma conexão que já estava estabelecida. Firewalls mal configurados deixam passar.",
        "hint": "Rode o comando com hping3 e verifique o log do IDS no painel.",
        "category": "wireshark"
    },
    {
        "id": 63,
        "title": "Bypass via Porta de Origem",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Com o Firewall ativo, realize uma varredura falsificando a porta de origem para 53 (DNS) e pegue a FLAG.",
        "cmd": "sudo nmap -sS --source-port 53 127.0.0.1 -p 9001",
        "help": "Muitos firewalls permitem que respostas DNS externas (porta 53) passem diretamente para a rede local.",
        "hint": "Use --source-port 53 no Nmap ou a porta FTP simulada responderá a FLAG.",
        "category": "wireshark"
    },
    {
        "id": 64,
        "title": "Fragmentação de Pacotes",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag simples do Nmap divide os cabeçalhos IP em pequenos fragmentos para dificultar a análise de IDSs?",
        "cmd": "nmap -f 127.0.0.1",
        "help": "Divide a requisição TCP em pedaços pequenos, remontados apenas no destino final.",
        "hint": "É a flag minúscula '-f'.",
        "category": "nmap"
    },
    {
        "id": 65,
        "title": "Configurando Tamanho de MTU",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual parâmetro do Nmap permite declarar explicitamente um tamanho de MTU customizado (múltiplo de 8)?",
        "cmd": "nmap --mtu 24 127.0.0.1",
        "help": "Controlar a unidade máxima de transmissão (MTU) permite evadir detecção de assinaturas de rede.",
        "hint": "Use '--mtu'.",
        "category": "nmap"
    },
    {
        "id": 66,
        "title": "Utilitário Injetor de Pacotes",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual ferramenta clássica do terminal Linux é usada para customização e injeção livre de pacotes TCP/IP?",
        "cmd": "",
        "help": "Permite simular ataques de flood, testar firewalls e realizar tracepaths com cabeçalhos arbitrários.",
        "hint": "hping3.",
        "category": "netcat"
    },
    {
        "id": 67,
        "title": "Hping3: Flag SYN",
        "difficulty": "fácil",
        "points": 50,
        "desc": "No hping3, qual parâmetro é usado para definir a flag SYN ativada no pacote de saída?",
        "cmd": "hping3 -S 127.0.0.1",
        "help": "O hping3 usa flags em maiúsculo para sinalizar cabeçalhos TCP.",
        "hint": "Use '-S'.",
        "category": "netcat"
    },
    {
        "id": 68,
        "title": "Hping3: Flag FIN",
        "difficulty": "fácil",
        "points": 50,
        "desc": "No hping3, qual parâmetro é usado para definir a flag FIN ativa no pacote?",
        "cmd": "",
        "help": "Envia o pacote sinalizando término de conexão.",
        "hint": "Use '-F'.",
        "category": "netcat"
    },
    {
        "id": 69,
        "title": "Hping3: Enviando Xmas",
        "difficulty": "difícil",
        "points": 150,
        "desc": "No hping3, qual combinação de parâmetros em maiúsculo ativa simultaneamente FIN, PSH e URG (Xmas)?",
        "cmd": "hping3 -F -P -U 127.0.0.1",
        "help": "Você pode combinar múltiplos argumentos separados por espaços.",
        "hint": "Responda com '-F -P -U'.",
        "category": "netcat"
    },
    {
        "id": 70,
        "title": "Idle Scan (Host Zombie)",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual flag do Nmap realiza a varredura Idle Scan, usando a contagem de ID de pacotes de um host intermediário (Zombie)?",
        "cmd": "nmap -sI zombie_ip 127.0.0.1",
        "help": "O atacante permanece invisível para o alvo, pois todo o tráfego aparenta vir do host zumbi.",
        "hint": "Combina o prefixo de scan '-s' com a letra maiúscula 'I' (Idle).",
        "category": "nmap"
    },
    {
        "id": 71,
        "title": "Bypass via NULL Scan",
        "difficulty": "médio",
        "points": 100,
        "desc": "Com o Firewall ativo, faça um NULL Scan no Nmap e recupere a FLAG liberada pelo sniffer IDS.",
        "cmd": "sudo nmap -sN 127.0.0.1 -p 9001",
        "help": "NULL Scan envia pacotes TCP sem nenhuma flag ativa. Rompe proteções que focam em comportamentos conhecidos.",
        "hint": "Execute e verifique imediatamente os novos logs do console IDS.",
        "category": "wireshark"
    },
    {
        "id": 72,
        "title": "Bypass via FIN Scan",
        "difficulty": "médio",
        "points": 100,
        "desc": "Com o Firewall ativo, execute um FIN Scan no Nmap e capture a FLAG exibida nos logs.",
        "cmd": "sudo nmap -sF 127.0.0.1 -p 9001",
        "help": "Usa apenas a flag FIN ativa. Útil para contornar proteções simples de filtragem.",
        "hint": "Procure por 'BYPASS SUCESSO' no terminal IDS do painel.",
        "category": "wireshark"
    },
    {
        "id": 73,
        "title": "Camuflagem por Decoy (Iscas)",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual técnica do Nmap insere IPs falsificados de outros hosts (iscas) misturados ao tráfego do atacante?",
        "cmd": "nmap -D decoy1,decoy2 127.0.0.1",
        "help": "Torna extremamente difícil identificar qual das conexões é a do verdadeiro invasor nos logs do alvo.",
        "hint": "Responda com o nome em inglês: 'Decoy' ou '-D'.",
        "category": "nmap"
    },
    {
        "id": 74,
        "title": "Flag do Decoy",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag do Nmap ativa o uso de Iscas (Decoys) na linha de comando?",
        "cmd": "",
        "help": "Requer privilégios de root para gerar pacotes com IPs forjados.",
        "hint": "Uma letra maiúscula precedida de traço: '-D'.",
        "category": "nmap"
    },
    {
        "id": 75,
        "title": "Pacotes Anômalos",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é a denominação técnica para pacotes TCP que violam os estados válidos da máquina de estados do TCP (ex: SYN+RST)?",
        "cmd": "",
        "help": "São amplamente filtrados por firewalls Stateful de nova geração.",
        "hint": "Escreva 'Pacotes Anômalos' ou 'Invalid Flags'.",
        "category": "wireshark"
    },
    {
        "id": 76,
        "title": "Firewall Stateful",
        "difficulty": "médio",
        "points": 100,
        "desc": "Como são chamados os firewalls que analisam o contexto e a tabela de conexões ativas (state table) em vez de apenas pacotes isolados?",
        "cmd": "",
        "help": "Eles lembram o fluxo de conexões passadas e barram pacotes avulsos (como ACK sem SYN anterior).",
        "hint": "Escreva 'Stateful'.",
        "category": "wireshark"
    },
    {
        "id": 77,
        "title": "Firewall Stateless",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual tipo de firewall antigo e simples apenas inspeciona cabeçalhos de pacotes de forma individual e isolada?",
        "cmd": "",
        "help": "Facilmente contornado por varreduras ACK ou pacotes fragmentados.",
        "hint": "Escreva 'Stateless'.",
        "category": "wireshark"
    },
    {
        "id": 78,
        "title": "Firewall Padrão do Linux",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual utilitário tradicional em linha de comando do Linux é usado para gerenciar as regras de firewall do Netfilter?",
        "cmd": "",
        "help": "Permite configurar tabelas de filtros e NAT no kernel.",
        "hint": "iptables.",
        "category": "nmap"
    },
    {
        "id": 79,
        "title": "Regra DROP no Firewall",
        "difficulty": "fácil",
        "points": 50,
        "desc": "No iptables, qual é a ação (target) que ignora totalmente um pacote, fazendo com que o cliente espere até o timeout?",
        "cmd": "",
        "help": "A ação DROP descarta o pacote sem responder de volta ao emissor.",
        "hint": "DROP.",
        "category": "nmap"
    },
    {
        "id": 80,
        "title": "Regra REJECT no Firewall",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual ação (target) do iptables rejeita o tráfego ativamente, enviando um pacote RST ou erro ICMP de volta?",
        "cmd": "",
        "help": "Diferente de DROP, a rejeição é comunicada imediatamente ao solicitante.",
        "hint": "REJECT.",
        "category": "nmap"
    },
    {
        "id": 81,
        "title": "Fuzzing de Banco Legado",
        "difficulty": "médio",
        "points": 100,
        "desc": "Use a ferramenta <code>ffuf</code> para encontrar o banco de dados legado do laboratório e capture a FLAG contida nele.",
        "cmd": "ffuf -u http://127.0.0.1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .sql -mc 200 -c",
        "help": "Substitua a porta de acesso se o lab estiver rodando na porta 8080. O ffuf é o fuzzer web mais rápido escrito em Go.",
        "hint": "O arquivo possui extensão .sql. Varra diretórios comuns.",
        "category": "ffuf"
    },
    {
        "id": 82,
        "title": "JWT Secret Exposto",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Faça fuzzing na API do laboratório para encontrar o arquivo de autenticação .json exposto. Qual é o segredo do JWT (jwt_secret)?",
        "cmd": "ffuf -u http://127.0.0.1/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .json -mc 200",
        "help": "Mapeie rotas da API em formato JSON para encontrar credenciais duras.",
        "hint": "A resposta é a chave secreta string listada no JSON (/api/v1/auth.json).",
        "category": "ffuf"
    },
    {
        "id": 83,
        "title": "Placeholder Reservado",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual palavra reservada (placeholder) em letras maiúsculas é usada no ffuf para indicar onde injetar as palavras da wordlist?",
        "cmd": "ffuf -u http://127.0.0.1/FUZZ -w wordlist.txt",
        "help": "O ffuf substitui essa tag por cada item do dicionário na URL ou cabeçalhos.",
        "hint": "FUZZ.",
        "category": "ffuf"
    },
    {
        "id": 84,
        "title": "Definindo a Wordlist",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag de argumento do ffuf é usada para declarar o caminho da lista de palavras (wordlist) de entrada?",
        "cmd": "",
        "help": "Esse parâmetro aceita caminhos absolutos ou relativos.",
        "hint": "Flag minúscula '-w'.",
        "category": "ffuf"
    },
    {
        "id": 85,
        "title": "Filtragem de Status HTTP",
        "difficulty": "médio",
        "points": 100,
        "desc": "No ffuf, qual flag serve para forçar o programa a listar apenas resultados que retornem códigos de status específicos (ex: 200,301)?",
        "cmd": "",
        "help": "Se não configurada, o ffuf pode retornar todos os códigos de resposta HTTP.",
        "hint": "Significa Match Codes. Use '-mc'.",
        "category": "ffuf"
    },
    {
        "id": 86,
        "title": "Ocultando Respostas por Tamanho",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag do ffuf serve para filtrar/ocultar respostas pelo tamanho exato em bytes (Filter Size)?",
        "cmd": "ffuf -u http://127.0.0.1/FUZZ -w wordlist.txt -fs 431",
        "help": "Excelente para omitir falsos positivos ou páginas de erro padrão que possuem o mesmo tamanho em bytes.",
        "hint": "Significa Filter Size. Use '-fs'.",
        "category": "ffuf"
    },
    {
        "id": 87,
        "title": "Adicionando Extensões de Arquivo",
        "difficulty": "médio",
        "points": 100,
        "desc": "No ffuf, qual flag permite especificar extensões de arquivo adicionais a serem anexadas na busca (ex: .php,.json)?",
        "cmd": "",
        "help": "Anexa as extensões definidas à palavra que está sendo fuzzada.",
        "hint": "Significa Extensions. Use '-e'.",
        "category": "ffuf"
    },
    {
        "id": 88,
        "title": "Modo Colorido",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag do ffuf ativa a formatação de terminal colorida para facilitar a leitura visual dos códigos HTTP?",
        "cmd": "",
        "help": "Coloriza saídas de 200 em verde, 301 em azul e 400+ em vermelho.",
        "hint": "Significa Color. Use '-c'.",
        "category": "ffuf"
    },
    {
        "id": 89,
        "title": "Filtro de Linhas",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag do ffuf serve para filtrar respostas com base na contagem exata de linhas da resposta (Filter Lines)?",
        "cmd": "",
        "help": "Usado para remover páginas repetitivas de erro do escaneamento.",
        "hint": "Significa Filter Lines. Use '-fl'.",
        "category": "ffuf"
    },
    {
        "id": 90,
        "title": "Filtro de Palavras",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual flag do ffuf filtra os resultados com base na contagem exata de palavras no corpo da resposta (Filter Words)?",
        "cmd": "",
        "help": "Ajuda a contornar redirecionamentos que contêm sempre a mesma quantidade de termos.",
        "hint": "Significa Filter Words. Use '-fw'.",
        "category": "ffuf"
    },
    {
        "id": 91,
        "title": "Código HTTP OK",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual código de status HTTP numérico de 3 dígitos indica que o recurso foi encontrado com sucesso (OK)?",
        "cmd": "",
        "help": "Status retornado para requisições bem-sucedidas.",
        "hint": "É o número 200.",
        "category": "ffuf"
    },
    {
        "id": 92,
        "title": "Código HTTP Redirecionamento",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual código HTTP de 3 dígitos representa um redirecionamento permanente do recurso?",
        "cmd": "",
        "help": "Indica que o recurso mudou permanentemente de URL.",
        "hint": "É o número 301.",
        "category": "ffuf"
    },
    {
        "id": 93,
        "title": "Código HTTP Acesso Negado",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual código HTTP de 3 dígitos representa 'Acesso Proibido/Proibido' (Forbidden)?",
        "cmd": "",
        "help": "Indica que o servidor entendeu a requisição mas recusa a autorização.",
        "hint": "É o número 403.",
        "category": "ffuf"
    },
    {
        "id": 94,
        "title": "Código HTTP Não Encontrado",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é o famoso código HTTP de 3 dígitos que indica que um arquivo ou página não foi encontrado no servidor?",
        "cmd": "",
        "help": "Código padrão emitido para diretórios inexistentes.",
        "hint": "É o número 404.",
        "category": "ffuf"
    },
    {
        "id": 95,
        "title": "Código HTTP Erro Interno",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual código HTTP de 3 dígitos indica que ocorreu um erro genérico não tratado dentro do servidor web (Internal Server Error)?",
        "cmd": "",
        "help": "Pode sinalizar erros de código ou crash na aplicação.",
        "hint": "É o número 500.",
        "category": "ffuf"
    },
    {
        "id": 96,
        "title": "Repositório SecLists",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é o nome do famoso repositório de wordlists de segurança (contendo diretórios comuns, senhas e payloads) muito usado no Kali?",
        "cmd": "",
        "help": "Facilita auditorias fornecendo dicionários profissionais testados na indústria.",
        "hint": "Escreva 'SecLists'.",
        "category": "ffuf"
    },
    {
        "id": 97,
        "title": "Pasta de Wordlists no Kali",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual é o caminho absoluto padrão da pasta principal onde o Kali Linux armazena seus dicionários e wordlists padrão?",
        "cmd": "",
        "help": "Normalmente abriga subpastas como seclists, dirb, dirbuster e rockyou.",
        "hint": "Começa com '/usr/share/wordlists'.",
        "category": "ffuf"
    },
    {
        "id": 98,
        "title": "Conceito de Soft 404",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Qual é a designação técnica dada a páginas web que retornam conteúdo de erro informando que o arquivo não existe, mas entregam o código de status HTTP 200?",
        "cmd": "",
        "help": "Pode confundir scanners automatizados que se baseiam puramente em cabeçalhos HTTP de status.",
        "hint": "Escreva 'Soft 404', 'Falso 404' ou 'Pagina customizada'.",
        "category": "ffuf"
    },
    {
        "id": 99,
        "title": "Alternativa Concorrente do ffuf",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual ferramenta em Go, que concorre diretamente com o ffuf, realiza fuzzing e mapeamento web via terminal?",
        "cmd": "gobuster dir -u http://127.0.0.1 -w wordlist.txt",
        "help": "Muito utilizada para enumeração de subdomínios, diretórios e hosts virtuais.",
        "hint": "gobuster.",
        "category": "ffuf"
    },
    {
        "id": 100,
        "title": "Método HTTP para Envio de Formulários",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual método HTTP (POST/GET/PUT) é classicamente usado para submeter dados de autenticação e formulários no corpo da requisição?",
        "cmd": "",
        "help": "Esse método insere dados de forma opaca aos parâmetros visíveis de URL.",
        "hint": "POST.",
        "category": "ffuf"
    },
    {
        "id": 101,
        "category": "nmap",
        "title": "Versão do FTP Oculto",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Use o Nmap para descobrir a versão exata do servidor FTP rodando na porta 9001. Qual é o nome/versão retornado?",
        "cmd": "nmap -sV -p 9001 127.0.0.1",
        "help": "A detecção de versão (-sV) envia probes específicos e extrai o banner retornado pelo protocolo.",
        "hint": "Varra a porta 9001 e veja a coluna 'VERSION'. Responda 'Alpha'."
    },
    {
        "id": 102,
        "category": "nmap",
        "title": "Mapeamento do Mock Server 9002",
        "difficulty": "médio",
        "points": 100,
        "desc": "Varra a porta TCP 9002 usando detecção de versão do Nmap. Qual é a versão do serviço que rodando nela?",
        "cmd": "nmap -sV -p 9002 127.0.0.1",
        "help": "O Nmap analisa os pacotes de resposta TCP para identificar assinaturas de serviços conhecidos.",
        "hint": "A versão retornada começa com 'v1'. Responda 'v1.0.0'."
    },
    {
        "id": 103,
        "category": "nmap",
        "title": "Varredura UDP Específica",
        "difficulty": "médio",
        "points": 100,
        "desc": "Qual porta UDP está aberta no localhost na faixa de 9000 a 9015? (Use varredura UDP do Nmap)",
        "cmd": "sudo nmap -sU -p 9000-9015 127.0.0.1",
        "help": "Varreduras UDP requerem privilégios de root (-sU) e costumam ser mais lentas que as TCP.",
        "hint": "A porta está entre 9005 e 9012. Responda '9009'."
    },
    {
        "id": 104,
        "category": "nmap",
        "title": "Varredura de Portas Altas",
        "difficulty": "médio",
        "points": 100,
        "desc": "Varra a faixa de portas TCP de 9500 a 9600 no localhost. Qual porta está aberta?",
        "cmd": "nmap -p 9500-9600 127.0.0.1",
        "help": "Muitos backdoors ou serviços de desenvolvimento sobem em portas altas incomuns para ocultação.",
        "hint": "A porta termina com '55'. Responda '9555'."
    },
    {
        "id": 105,
        "category": "netcat",
        "title": "Banner Grabbing na Porta 9002",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se na porta TCP 9002 usando netcat. Qual é a FLAG exibida no banner de boas-vindas?",
        "cmd": "nc 127.0.0.1 9002",
        "help": "O netcat estabelece conexões TCP diretas e imprime na tela qualquer dado enviado pelo servidor.",
        "hint": "Conecte usando 'nc 127.0.0.1 9002' e copie a FLAG."
    },
    {
        "id": 106,
        "category": "netcat",
        "title": "Interação via Porta 9002",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se à porta TCP 9002 e envie a mensagem 'banana'. Qual flag é retornada como resposta?",
        "cmd": "echo 'banana' | nc 127.0.0.1 9002",
        "help": "Serviços interativos respondem de forma diferente de acordo com a entrada enviada pelo cliente.",
        "hint": "Envie 'banana' usando echo e pipe para o netcat."
    },
    {
        "id": 107,
        "category": "netcat",
        "title": "Banner do Servidor SMTP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se à porta SMTP simulada (9003) via netcat. Qual é a primeira palavra/número no banner de boas-vindas?",
        "cmd": "nc 127.0.0.1 9003",
        "help": "Servidores SMTP seguem a RFC e sempre iniciam a resposta com o código de status HTTP/SMTP 220.",
        "hint": "A primeira palavra é o código de status SMTP. Responda '220'."
    },
    {
        "id": 108,
        "category": "netcat",
        "title": "Início de Sessão SMTP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "No simulador SMTP (porta 9003), inicie a sessão enviando o comando 'HELO local'. O que o servidor responde após isso?",
        "cmd": "nc 127.0.0.1 9003",
        "help": "O comando HELO é usado para se identificar para o servidor SMTP e iniciar o diálogo de e-mail.",
        "hint": "Escreva 'HELO local' após conectar. Resposta começa com '250'."
    },
    {
        "id": 109,
        "category": "netcat",
        "title": "Enumeração de Usuários SMTP",
        "difficulty": "médio",
        "points": 100,
        "desc": "No simulador SMTP (porta 9003), envie o comando 'VRFY admin'. Qual flag confirma o sucesso da enumeração de usuários?",
        "cmd": "nc 127.0.0.1 9003",
        "help": "O comando VRFY permite validar se um determinado e-mail ou usuário existe no servidor.",
        "hint": "Envie 'VRFY admin' após conectar e copie a FLAG retornada."
    },
    {
        "id": 110,
        "category": "netcat",
        "title": "Prompt do Serviço Telnet",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se ao serviço Telnet simulado na porta 9004 via netcat. Qual prompt de login é retornado?",
        "cmd": "nc 127.0.0.1 9004",
        "help": "Serviços Telnet não criptografados exibem um prompt de login direto na tela de conexão.",
        "hint": "Conecte-se e digite a palavra do prompt que pede o usuário (com dois pontos). Responda 'Username:'."
    },
    {
        "id": 111,
        "category": "netcat",
        "title": "Autenticação Telnet",
        "difficulty": "médio",
        "points": 100,
        "desc": "No serviço Telnet simulado (porta 9004), faça login usando o usuário 'admin' e a senha 'admin'. Qual flag é impressa?",
        "cmd": "nc 127.0.0.1 9004",
        "help": "Após a conexão, envie as credenciais sequencialmente quando solicitadas pelo terminal.",
        "hint": "Insira 'admin' no usuário e 'admin' na senha."
    },
    {
        "id": 112,
        "category": "netcat",
        "title": "Leitura de Banner MySQL",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se ao serviço MySQL simulado na porta 9006 usando o netcat. O banner contém um hash no final. Qual é a flag presente nesse hash?",
        "cmd": "nc 127.0.0.1 9006",
        "help": "O MySQL envia um pacote inicial contendo a versão do servidor e dados de handshake de autenticação.",
        "hint": "Conecte-se via nc na porta 9006 e copie a FLAG{...} exibida no banner de texto cru."
    },
    {
        "id": 113,
        "category": "netcat",
        "title": "Comando Ping no Redis",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se ao serviço Redis simulado na porta 9008 via netcat e envie o comando 'ping'. O que o Redis responde?",
        "cmd": "echo 'ping' | nc 127.0.0.1 9008",
        "help": "O Redis possui um protocolo simples baseado em texto. O comando 'ping' serve para testar a conectividade.",
        "hint": "O Redis responde com a palavra padrão de sucesso. Responda 'PONG'."
    },
    {
        "id": 114,
        "category": "netcat",
        "title": "Obtenção de Chaves no Redis",
        "difficulty": "médio",
        "points": 100,
        "desc": "No serviço Redis simulado (porta 9008), envie o comando 'get flag'. Qual flag secreta é retornada?",
        "cmd": "echo 'get flag' | nc 127.0.0.1 9008",
        "help": "O Redis armazena dados em pares chave-valor. O comando GET recupera o valor associado a uma chave.",
        "hint": "Envie 'get flag' e copie a FLAG{...} retornada."
    },
    {
        "id": 115,
        "category": "netcat",
        "title": "Requisição HTTP Manual",
        "difficulty": "médio",
        "points": 100,
        "desc": "Na porta HTTP principal (80 ou 8080), qual flag é revelada ao enviar a requisição manual 'GET /nc-flag HTTP/1.0\\r\\n\\r\\n' usando netcat?",
        "cmd": "echo -ne 'GET /nc-flag HTTP/1.0\\r\\n\\r\\n' | nc 127.0.0.1 80",
        "help": "O protocolo HTTP é baseado em texto. Podemos estruturar requisições manualmente usando netcat e quebras de linha.",
        "hint": "Substitua a porta por 8080 se o seu site estiver rodando nela."
    },
    {
        "id": 116,
        "category": "netcat",
        "title": "Fuzzing de Cookies via Netcat",
        "difficulty": "médio",
        "points": 100,
        "desc": "Envie uma requisição HTTP na porta principal pedindo por '/cookie-flag' via netcat. Qual flag é exibida no corpo de resposta?",
        "cmd": "echo -ne 'GET /cookie-flag HTTP/1.0\\r\\n\\r\\n' | nc 127.0.0.1 80",
        "help": "Servidores HTTP tratam rotas específicas respondendo dados ou flags.",
        "hint": "Mande a requisição GET /cookie-flag HTTP/1.0 na porta correta (80 ou 8080) e copie a FLAG."
    },
    {
        "id": 117,
        "category": "netcat",
        "title": "Banner do Servidor POP3",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se ao serviço POP3 simulado na porta 9110 via netcat. Qual é a string inicial de boas-vindas do servidor?",
        "cmd": "nc 127.0.0.1 9110",
        "help": "O protocolo POP3 de recebimento de e-mails sempre inicia respostas positivas com a string '+OK'.",
        "hint": "A string é '+OK POP3 Server Ready'. copie e cole exatamente."
    },
    {
        "id": 118,
        "category": "netcat",
        "title": "Identificação de Usuário POP3",
        "difficulty": "fácil",
        "points": 50,
        "desc": "No simulador POP3 (porta 9110), faça o comando 'USER admin'. Qual é a resposta obtida?",
        "cmd": "nc 127.0.0.1 9110",
        "help": "O comando USER inicia o processo de autenticação indicando o nome da caixa de correio.",
        "hint": "Envie 'USER admin' após conectar. Responda '+OK Welcome admin'."
    },
    {
        "id": 119,
        "category": "netcat",
        "title": "Autenticação Completa POP3",
        "difficulty": "médio",
        "points": 100,
        "desc": "No simulador POP3 (porta 9110), faça login com 'USER admin' e 'PASS admin'. Qual flag secreta é exibida após o login bem-sucedido?",
        "cmd": "nc 127.0.0.1 9110",
        "help": "Após fornecer o usuário com USER, digite PASS seguido da senha para efetivar a autenticação.",
        "hint": "Insira os comandos sequencialmente e copie a FLAG{...} de resposta."
    },
    {
        "id": 120,
        "category": "netcat",
        "title": "Banner do Servidor IMAP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Conecte-se ao serviço IMAP simulado na porta 9143 via netcat. Qual é a string do banner inicial retornado?",
        "cmd": "nc 127.0.0.1 9143",
        "help": "O protocolo IMAP também serve para e-mails e inicia sua conexão com '* OK' seguido de detalhes.",
        "hint": "A resposta inicial é '* OK IMAP Server Ready'. Cole exatamente."
    },
    {
        "id": 121,
        "category": "netcat",
        "title": "Autenticação no IMAP",
        "difficulty": "médio",
        "points": 100,
        "desc": "No simulador IMAP (porta 9143), envie o comando 'A1 LOGIN admin admin'. Qual flag é retornada como resposta do servidor?",
        "cmd": "nc 127.0.0.1 9143",
        "help": "No IMAP, comandos devem ser prefixados com uma tag alfanumérica única (como A1) pelo cliente.",
        "hint": "Digite 'A1 LOGIN admin admin' e copie a FLAG{...} no retorno."
    },
    {
        "id": 122,
        "category": "netcat",
        "title": "Modificação de User-Agent via Netcat",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Acesse a página principal solicitando '/agent-flag' usando netcat com o cabeçalho 'User-Agent: admin-browser'. Qual flag é retornada?",
        "cmd": "echo -ne 'GET /agent-flag HTTP/1.0\\r\\nUser-Agent: admin-browser\\r\\n\\r\\n' | nc 127.0.0.1 80",
        "help": "Servidores web podem filtrar o acesso a recursos com base no navegador declarado (User-Agent).",
        "hint": "Envie o cabeçalho User-Agent: admin-browser na rota /agent-flag. Lembre-se da porta (80 ou 8080)."
    },
    {
        "id": 123,
        "category": "netcat",
        "title": "Envio de Sessão em Cookie via Netcat",
        "difficulty": "difícil",
        "points": 150,
        "desc": "Envie uma requisição HTTP solicitando '/session-flag' usando netcat com o cabeçalho 'Cookie: session=admin'. Qual flag é retornada?",
        "cmd": "echo -ne 'GET /session-flag HTTP/1.0\\r\\nCookie: session=admin\\r\\n\\r\\n' | nc 127.0.0.1 80",
        "help": "Cookies de sessão identificam usuários autenticados. Injetar um cookie administrativo simula sequestro de sessão.",
        "hint": "Adicione o cabeçalho Cookie: session=admin na rota /session-flag."
    },
    {
        "id": 124,
        "category": "wireshark",
        "title": "Valor Hexadecimal da Flag URG",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual é o valor hexadecimal exato do campo flags em um pacote TCP com apenas a flag URG ativada?",
        "cmd": "",
        "help": "Cada flag TCP ocupa um bit no byte de flags do cabeçalho TCP. A flag URG é o bit correspondente a 32 (decimal).",
        "hint": "O valor em hexadecimal para decimal 32 é '0x20' ou '0x020'."
    },
    {
        "id": 125,
        "category": "wireshark",
        "title": "Identificação de Log de Bloqueio",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Se o firewall do lab estiver ativo e bloquear uma conexão, qual string exata é gravada na coluna 'Flags' do IDS Console?",
        "cmd": "",
        "help": "O firewall simula o bloqueio descartando pacotes. O IDS registra isso com um marcador especial na tabela de tráfego.",
        "hint": "Consulte o IDS Console ao realizar uma varredura bloqueada. Responda 'DROP (Bloqueado)'."
    },
    {
        "id": 126,
        "category": "wireshark",
        "title": "Bypass Xmas Live",
        "difficulty": "médio",
        "points": 100,
        "desc": "Ative o Firewall do lab. Execute um scan Xmas na porta 9001 e obtenha a flag de bypass no console ou saída.",
        "cmd": "sudo nmap -sX -p 9001 127.0.0.1",
        "help": "O scan Xmas envia flags FIN, PSH e URG que passam por firewalls stateless mal configurados.",
        "hint": "A flag é a mesma do desafio de teoria Xmas: 'FLAG{XM4S_F1R3W4LL_BYP4SS}'."
    },
    {
        "id": 127,
        "category": "wireshark",
        "title": "Bypass NULL Live",
        "difficulty": "médio",
        "points": 100,
        "desc": "Ative o Firewall do lab. Execute um scan NULL na porta 9001 e obtenha a flag de bypass.",
        "cmd": "sudo nmap -sN -p 9001 127.0.0.1",
        "help": "O NULL scan não seta nenhuma flag TCP, burlando regras de filtragem baseadas em estado simples.",
        "hint": "A flag é 'FLAG{NULL_F1R3W4LL_BYP4SS}'."
    },
    {
        "id": 128,
        "category": "wireshark",
        "title": "Bypass FIN Live",
        "difficulty": "médio",
        "points": 100,
        "desc": "Ative o Firewall do lab. Execute um scan FIN na porta 9001 e obtenha a flag de bypass.",
        "cmd": "sudo nmap -sF -p 9001 127.0.0.1",
        "help": "O scan FIN envia apenas pacotes com a flag FIN ativada.",
        "hint": "A flag é 'FLAG{FIN_F1R3W4LL_BYP4SS}'."
    },
    {
        "id": 129,
        "category": "wireshark",
        "title": "Bypass Porta de Origem Live",
        "difficulty": "médio",
        "points": 100,
        "desc": "Ative o Firewall do lab. Realize um scan SYN comum na porta 9001 com a porta de origem (source port) configurada como 53 (DNS). Qual flag é retornada?",
        "cmd": "sudo nmap -sS -p 9001 -g 53 127.0.0.1",
        "help": "A opção -g ou --source-port força o Nmap a enviar probes a partir de uma porta confiável.",
        "hint": "A flag é 'FLAG{SRCPORT_F1R3W4LL_BYP4SS}'."
    },
    {
        "id": 130,
        "category": "wireshark",
        "title": "Captura de Flag Múltipla no IDS",
        "difficulty": "médio",
        "points": 100,
        "desc": "No console do IDS, ao enviar um pacote com as flags SYN e ACK habilitadas ao mesmo tempo, qual string é mostrada sob a coluna 'Flags'?",
        "cmd": "",
        "help": "O Raw Sniffer agrupa as flags ativas concatenando seus nomes com um sinal de mais (+).",
        "hint": "Escreva 'SYN+ACK'."
    },
    {
        "id": 131,
        "category": "ffuf",
        "title": "Fuzzing de Área Secreta",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Fuzze a raiz do site para encontrar um diretório oculto. O que está escrito no arquivo '/secret-area/flag.txt'?",
        "cmd": "ffuf -u http://127.0.0.1/FUZZ -w /usr/share/wordlists/dirb/common.txt",
        "help": "Varreduras de diretórios revelam pastas esquecidas por desenvolvedores.",
        "hint": "Pesquise por '/secret-area/flag.txt'. Flag: 'FLAG{FFUF_SECRET_AREA_FOUND}'."
    },
    {
        "id": 132,
        "category": "ffuf",
        "title": "Fuzzing de Caminhos PHP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Encontre a flag escondida na página '/vulnerable/login.php' do servidor do lab.",
        "cmd": "curl http://127.0.0.1/vulnerable/login.php",
        "help": "Mapear páginas de login é crucial na fase de enumeração web.",
        "hint": "Flag: 'FLAG{FFUF_LOGIN_PATH_DISCOVERED}'."
    },
    {
        "id": 133,
        "category": "ffuf",
        "title": "Fuzzing de Backups do DB",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag é encontrada ao baixar o arquivo '/backup.sql' exposto na raiz do servidor web?",
        "cmd": "curl http://127.0.0.1/backup.sql",
        "help": "Arquivos de backup expostos contêm dumps SQL com dados sensíveis de usuários.",
        "hint": "Flag: 'FLAG{FFUF_DATABASE_BACKUP_EXPOSED}'."
    },
    {
        "id": 134,
        "category": "ffuf",
        "title": "Webshell de Teste Detectado",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag é revelada na página '/uploads/shell.php' que simula um webshell de teste no servidor?",
        "cmd": "curl http://127.0.0.1/uploads/shell.php",
        "help": "Webshells expostas em pastas de upload fornecem execução remota de código.",
        "hint": "Flag: 'FLAG{FFUF_WEBSHELL_UPLOADED}'."
    },
    {
        "id": 135,
        "category": "ffuf",
        "title": "Vazamento de Configuração de Dev",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Investigue o diretório de desenvolvimento. Qual flag está contida no arquivo '/dev/config.json'?",
        "cmd": "curl http://127.0.0.1/dev/config.json",
        "help": "Arquivos JSON em pastas /dev frequentemente contêm segredos e chaves de API expostas.",
        "hint": "Flag: 'FLAG{FFUF_DEV_CONFIG_LEAK}'."
    },
    {
        "id": 136,
        "category": "ffuf",
        "title": "Auditoria de Logs Expostos",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta no arquivo de log de administrador '/admin/logs.txt'?",
        "cmd": "curl http://127.0.0.1/admin/logs.txt",
        "help": "Logs do sistema expostos revelam atividades de usuários e dados de depuração.",
        "hint": "Flag: 'FLAG{FFUF_ADMIN_LOGS_ACCESSIBLE}'."
    },
    {
        "id": 137,
        "category": "ffuf",
        "title": "Enumeração de API REST",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta ao acessar a rota da API '/api/v1/users'?",
        "cmd": "curl http://127.0.0.1/api/v1/users",
        "help": "Endpoints de APIs sem autenticação vazam bancos inteiros de usuários.",
        "hint": "Flag: 'FLAG{FFUF_API_USERS_EXPOSED}'."
    },
    {
        "id": 138,
        "category": "ffuf",
        "title": "Vazamento de Banco de Sessão",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está no arquivo de banco de dados temporário '/tmp/session.db' exposto?",
        "cmd": "curl http://127.0.0.1/tmp/session.db",
        "help": "Bancos SQLite temporários contêm sessões ativas e hashes de login.",
        "hint": "Flag: 'FLAG{FFUF_SESSION_DB_FOUND}'."
    },
    {
        "id": 139,
        "category": "ffuf",
        "title": "Cópia de Segurança JS",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está no arquivo de backup de script '/assets/js/main.js.bak'?",
        "cmd": "curl http://127.0.0.1/assets/js/main.js.bak",
        "help": "Extensões .bak ou .old contêm o código fonte original antes de correções de segurança.",
        "hint": "Flag: 'FLAG{FFUF_JS_BACKUP_LEAK}'."
    },
    {
        "id": 140,
        "category": "ffuf",
        "title": "Vazamento de Documento Interno",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está no documento PDF interno '/docs/internal_rules.pdf' simulado?",
        "cmd": "curl http://127.0.0.1/docs/internal_rules.pdf",
        "help": "Manuais e regulamentos internos vazados contêm regras de negócios sensíveis.",
        "hint": "Flag: 'FLAG{FFUF_INTERNAL_DOCS}'."
    },
    {
        "id": 141,
        "category": "ffuf",
        "title": "Diagnóstico do Servidor PHP",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag é exposta na página informativa de servidor '/info.php'?",
        "cmd": "curl http://127.0.0.1/info.php",
        "help": "A função phpinfo() expõe variáveis de ambiente, caminhos e extensões ativas do servidor.",
        "hint": "Flag: 'FLAG{FFUF_INFO_PHP_EXPOSED}'."
    },
    {
        "id": 142,
        "category": "ffuf",
        "title": "Status da Aplicação",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta na página de status '/server-status' do Apache simulado?",
        "cmd": "curl http://127.0.0.1/server-status",
        "help": "A página server-status exibe as requisições de clientes ativas e estatísticas do servidor.",
        "hint": "Flag: 'FLAG{FFUF_SERVER_STATUS_VIEW}'."
    },
    {
        "id": 143,
        "category": "ffuf",
        "title": "Vazamento do Repositório Git",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta no arquivo de configuração do repositório Git em '/.git/config'?",
        "cmd": "curl http://127.0.0.1/.git/config",
        "help": "Pastas .git expostas permitem baixar todo o código fonte da aplicação.",
        "hint": "Flag: 'FLAG{FFUF_GIT_CONFIG_LEAK}'."
    },
    {
        "id": 144,
        "category": "ffuf",
        "title": "Arquivo robots.txt",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está escrita dentro do arquivo regulador '/robots.txt' na raiz do servidor?",
        "cmd": "curl http://127.0.0.1/robots.txt",
        "help": "O robots.txt indica a robôs de busca quais diretórios não devem ser indexados, listando rotas ocultas.",
        "hint": "Flag: 'FLAG{FFUF_ROBOTS_TXT_FOUND}'."
    },
    {
        "id": 145,
        "category": "ffuf",
        "title": "Vazamento WP Config",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag é revelada no arquivo de configuração do WordPress '/wp-config.php' simulado?",
        "cmd": "curl http://127.0.0.1/wp-config.php",
        "help": "O arquivo wp-config armazena credenciais de banco de dados e chaves criptográficas em texto cru.",
        "hint": "Flag: 'FLAG{FFUF_WP_CONFIG_LEAK}'."
    },
    {
        "id": 146,
        "category": "ffuf",
        "title": "Painel phpMyAdmin Exposto",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está na página de administração de banco '/phpmyadmin/index.php' simulada?",
        "cmd": "curl http://127.0.0.1/phpmyadmin/index.php",
        "help": "Gerenciadores de banco de dados expostos na web facilitam ataques de força bruta.",
        "hint": "Flag: 'FLAG{FFUF_PHPMYADMIN_FOUND}'."
    },
    {
        "id": 147,
        "category": "ffuf",
        "title": "Execução de Scripts CGI",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta na rota '/test.cgi' de execução de scripts de teste?",
        "cmd": "curl http://127.0.0.1/test.cgi",
        "help": "Diretórios cgi-bin antigos costumam abrigar scripts de depuração vulneráveis.",
        "hint": "Flag: 'FLAG{FFUF_CGI_TEST_EXPOSED}'."
    },
    {
        "id": 148,
        "category": "ffuf",
        "title": "Arquivo de Ambiente Global",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está contida no arquivo de configuração de variáveis de ambiente '/.env'?",
        "cmd": "curl http://127.0.0.1/.env",
        "help": "O arquivo .env armazena credenciais de banco de dados, chaves de email e segredos JWT.",
        "hint": "Flag: 'FLAG{FFUF_ENV_FILE_LEAK}'."
    },
    {
        "id": 149,
        "category": "ffuf",
        "title": "Pasta node_modules Exposta",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está exposta na pasta de dependências do Node '/node_modules/'?",
        "cmd": "curl http://127.0.0.1/node_modules/",
        "help": "Deixar a pasta node_modules acessível vaza as dependências e versões de bibliotecas da aplicação.",
        "hint": "Flag: 'FLAG{FFUF_NODE_MODULES_EXPOSED}'."
    },
    {
        "id": 150,
        "category": "ffuf",
        "title": "Console de Desenvolvimento",
        "difficulty": "fácil",
        "points": 50,
        "desc": "Qual flag está na rota de console de desenvolvimento '/console'?",
        "cmd": "curl http://127.0.0.1/console",
        "help": "Consoles interativos deixados ativos fornecem acesso rápido a recursos internos do servidor.",
        "hint": "Flag: 'FLAG{FFUF_DEVELOPER_CONSOLE_LEAK}'."
    }
];

    // --- RESPOSTAS OFICIAIS (GABARITO) PARA EXIBIÇÃO NO CLIENTE ---
    const OFFICIAL_ANSWERS = {
        1: "9001", 2: "-sT", 3: "-sS", 4: "-p", 5: "-p-", 6: "-Pn", 7: "-O", 8: "-sV", 9: "-T4", 10: "-T0",
        11: "1000", 12: "-oN", 13: "-oG", 14: "-oX", 15: "-oA", 16: "-sU", 17: "Fechada", 18: "Filtrada", 19: "ARP", 20: "default",
        21: "FLAG{B4NN3R_GR4BB1NG_SUCC3SS}", 22: "netcat", 23: "22", 24: "21", 25: "25", 26: "53", 27: "80", 28: "443", 29: "3306", 30: "3389",
        31: "Versão", 32: "--version-intensity", 33: "Lua", 34: "NSE", 35: "vuln", 36: "auth", 37: "--script", 38: "/usr/share/nmap/scripts", 39: "nmap --script-updatedb", 40: "220",
        41: "FIN", 42: "SYN", 43: "ACK", 44: "RST", 45: "PSH", 46: "URG", 47: "SYN-ACK", 48: "tcp.port == 9001", 49: "tcp.flags.syn == 1 and tcp.flags.ack == 0", 50: "RST",
        51: "0x29", 52: "Nada", 53: "RST", 54: "RFC 793", 55: "RFC 9293", 56: "ip.src ==", 57: "http.request.method == \"POST\"", 58: "UDP", 59: "Port Unreachable", 60: "tshark",
        61: "FLAG{XM4S_F1R3W4LL_BYP4SS}", 62: "FLAG{ACK_F1R3W4LL_BYP4SS}", 63: "FLAG{SRCPORT_F1R3W4LL_BYP4SS}", 64: "-f", 65: "--mtu", 66: "hping3", 67: "-S", 68: "-F", 69: "-F -P -U", 70: "Idle Scan",
        71: "FLAG{NULL_F1R3W4LL_BYP4SS}", 72: "FLAG{FIN_F1R3W4LL_BYP4SS}", 73: "Decoy", 74: "-D", 75: "Pacotes Anômalos", 76: "Stateful", 77: "Stateless", 78: "iptables", 79: "DROP", 80: "REJECT",
        81: "FLAG{D4T4B4S3_DUMP_EXPOSED}", 82: "sup3r_s3cr3t", 83: "FUZZ", 84: "-w", 85: "-mc", 86: "-fs", 87: "-e", 88: "-c", 89: "-fl", 90: "-fw",
        91: "200", 92: "301", 93: "403", 94: "404", 95: "500", 96: "SecLists", 97: "/usr/share/wordlists", 98: "Falso 404", 99: "gobuster", 100: "POST",
        101: "Alpha", 102: "v1.0.0", 103: "9009", 104: "9555", 105: "FLAG{NC_WELCOME_9002}", 106: "FLAG{NC_BANANA_OK}", 107: "220", 108: "250 Hello", 109: "FLAG{SMTP_USER_ENUM_SUCCESS}", 110: "Username:",
        111: "FLAG{TELNET_LOGIN_BYPASS}", 112: "FLAG{MYSQL_BANNER_EXPOSED}", 113: "PONG", 114: "FLAG{REDIS_GET_FLAG_SUCCESS}", 115: "FLAG{NC_GET_REQUEST_OK}", 116: "FLAG{HTTP_COOKIE_CHECK}", 117: "+OK POP3 Server Ready", 118: "+OK Welcome admin", 119: "FLAG{POP3_LOGIN_SUCCESS}", 120: "* OK IMAP Server Ready",
        121: "FLAG{IMAP_LOGIN_SUCCESS}", 122: "FLAG{USER_AGENT_ADMIN}", 123: "FLAG{COOKIE_ADMIN}", 124: "0x20", 125: "DROP (Bloqueado)", 126: "FLAG{XM4S_F1R3W4LL_BYP4SS}", 127: "FLAG{NULL_F1R3W4LL_BYP4SS}", 128: "FLAG{FIN_F1R3W4LL_BYP4SS}", 129: "FLAG{SRCPORT_F1R3W4LL_BYP4SS}", 130: "SYN+ACK",
        131: "FLAG{FFUF_SECRET_AREA_FOUND}", 132: "FLAG{FFUF_LOGIN_PATH_DISCOVERED}", 133: "FLAG{FFUF_DATABASE_BACKUP_EXPOSED}", 134: "FLAG{FFUF_WEBSHELL_UPLOADED}", 135: "FLAG{FFUF_DEV_CONFIG_LEAK}", 136: "FLAG{FFUF_ADMIN_LOGS_ACCESSIBLE}", 137: "FLAG{FFUF_API_USERS_EXPOSED}", 138: "FLAG{FFUF_SESSION_DB_FOUND}", 139: "FLAG{FFUF_JS_BACKUP_LEAK}", 140: "FLAG{FFUF_INTERNAL_DOCS}",
        141: "FLAG{FFUF_INFO_PHP_EXPOSED}", 142: "FLAG{FFUF_SERVER_STATUS_VIEW}", 143: "FLAG{FFUF_GIT_CONFIG_LEAK}", 144: "FLAG{FFUF_ROBOTS_TXT_FOUND}", 145: "FLAG{FFUF_WP_CONFIG_LEAK}", 146: "FLAG{FFUF_PHPMYADMIN_FOUND}", 147: "FLAG{FFUF_CGI_TEST_EXPOSED}", 148: "FLAG{FFUF_ENV_FILE_LEAK}", 149: "FLAG{FFUF_NODE_MODULES_EXPOSED}", 150: "FLAG{FFUF_DEVELOPER_CONSOLE_LEAK}"
    };

    // --- ESTADO GERAL DA APLICAÇÃO ---
    const state = {
        solvedChallenges: [], // IDs resolvidos
        solvedAnswers: {}, // ID -> Resposta correta submetida
        usedHints: [], // IDs onde dicas foram reveladas
        hintsUsedCount: 0, // Máximo 5
        idsLogsPaused: false,
        scansCount: 0,
        stealthCount: 0,
        eventSource: null,
        firewallActive: false,
        activeModuleFilter: 'all',
        activeDifficultyFilter: 'all',
        searchQuery: ''
    };

    // --- CALCULAR TOTAL SCORE ---
    const calculateTotalScore = () => {
        let total = 0;
        state.solvedChallenges.forEach(id => {
            const ch = ALL_CHALLENGES.find(c => c.id === id);
            if (ch) {
                const penalty = state.usedHints.includes(id) ? 0.9 : 1.0;
                total += Math.round(ch.points * penalty);
            }
        });
        return total;
    };

    // --- CONTADOR DE DICAS POR CATEGORIA ---
    const getCategoryHintsCount = (category) => {
        return state.usedHints.filter(id => {
            const ch = ALL_CHALLENGES.find(c => c.id === id);
            return ch && ch.category === category;
        }).length;
    };

    // --- ATUALIZAR INDICADOR DE DICAS NA TELA DE CTF ---
    const updateHintsCountUI = () => {
        const cat = state.activeModuleFilter;
        const hintsCountEl = document.getElementById('hints-count');
        if (!hintsCountEl) return;
        
        if (cat === 'all') {
            hintsCountEl.textContent = `${state.usedHints.length} Totais`;
            hintsCountEl.className = "text-primary";
        } else {
            const count = getCategoryHintsCount(cat);
            hintsCountEl.textContent = `${count}/5 na categoria`;
            if (count >= 5) {
                hintsCountEl.className = "text-danger";
            } else if (count > 0) {
                hintsCountEl.className = "text-warning";
            } else {
                hintsCountEl.className = "text-primary";
            }
        }
    };

    // --- ATUALIZAR INTERFACE DE DESEMPENHO (DASHBOARD) ---
    const updatePerformanceUI = () => {
        const totalScore = calculateTotalScore();
        
        const perfTotalScoreEl = document.getElementById('perf-total-score');
        const statsScoreHeaderEl = document.getElementById('stats-score-header');
        if (perfTotalScoreEl) perfTotalScoreEl.textContent = `${totalScore} Pts`;
        if (statsScoreHeaderEl) statsScoreHeaderEl.textContent = `${totalScore} Pts`;

        const solvedCount = state.solvedChallenges.length;
        const totalChallengesCount = ALL_CHALLENGES.length; // 150
        const completionPct = totalChallengesCount > 0 ? Math.round((solvedCount / totalChallengesCount) * 100) : 0;
        
        const perfCompletionPctEl = document.getElementById('perf-completion-pct');
        const perfSolvedFractionEl = document.getElementById('perf-solved-fraction');
        if (perfCompletionPctEl) perfCompletionPctEl.textContent = `${completionPct}%`;
        if (perfSolvedFractionEl) perfSolvedFractionEl.textContent = `${solvedCount} de ${totalChallengesCount} resolvidos`;

        // Perfil Hacker baseado em pontuação ou desafios resolvidos
        let profile = "Script Kiddie";
        let profileDesc = "Iniciando na arte da varredura de redes.";
        if (solvedCount >= 120) {
            profile = "Elite Hacker (Root)";
            profileDesc = "Você dominou o laboratório. Respeito máximo!";
        } else if (solvedCount >= 80) {
            profile = "Cyber Operator";
            profileDesc = "Excelente domínio de evasão e automação.";
        } else if (solvedCount >= 40) {
            profile = "Security Analyst";
            profileDesc = "Capaz de realizar análises e varreduras intermediárias.";
        } else if (solvedCount > 5) {
            profile = "Pentester Aprendiz";
            profileDesc = "Adquirindo conceitos práticos de redes.";
        }
        
        const perfHackerProfileEl = document.getElementById('perf-hacker-profile');
        const perfHackerDescEl = document.getElementById('perf-hacker-desc');
        if (perfHackerProfileEl) perfHackerProfileEl.textContent = profile;
        if (perfHackerDescEl) perfHackerDescEl.textContent = profileDesc;

        // Porcentagem de conclusão por categoria
        const categories = ['nmap', 'netcat', 'wireshark', 'ffuf'];
        const catStats = {};

        categories.forEach(cat => {
            const catChs = ALL_CHALLENGES.filter(c => c.category === cat);
            const totalCat = catChs.length;
            const solvedCat = catChs.filter(c => state.solvedChallenges.includes(c.id)).length;
            const pct = totalCat > 0 ? Math.round((solvedCat / totalCat) * 100) : 0;

            catStats[cat] = { total: totalCat, solved: solvedCat, pct: pct };

            // Atualizar barras de progresso na UI
            const barFill = document.getElementById(`bar-fill-${cat}`);
            const barPct = document.getElementById(`bar-pct-${cat}`);
            if (barFill) barFill.style.width = `${pct}%`;
            if (barPct) barPct.textContent = `${pct}%`;

            // Atualizar contagem de dicas de cada categoria na UI do desempenho
            const hintsCountEl = document.getElementById(`perf-hints-${cat}`);
            if (hintsCountEl) {
                const used = getCategoryHintsCount(cat);
                hintsCountEl.textContent = `${used}/5`;
                if (used >= 5) {
                    hintsCountEl.className = "text-danger";
                } else if (used > 0) {
                    hintsCountEl.className = "text-warning";
                } else {
                    hintsCountEl.className = "";
                }
            }
        });

        // Pontos Fortes e Fracos
        const strengthsList = document.getElementById('perf-strengths-list');
        const weaknessesList = document.getElementById('perf-weaknesses-list');
        
        if (strengthsList && weaknessesList) {
            strengthsList.innerHTML = '';
            weaknessesList.innerHTML = '';

            let strengthsCount = 0;
            let weaknessesCount = 0;

            const catNamesFriendly = {
                'nmap': "Nmap (Varredura Ativa)",
                'netcat': "Netcat (Conexão e Portas)",
                'wireshark': "Wireshark (Análise L4)",
                'ffuf': "Ffuf & Gobuster (Fuzzing Web)"
            };

            categories.forEach(cat => {
                const stats = catStats[cat];
                if (stats.solved > 0 && stats.pct >= 50) {
                    const li = document.createElement('li');
                    li.innerHTML = `<strong>${catNamesFriendly[cat]}:</strong> Domínio de ${stats.pct}% (${stats.solved}/${stats.total} resolvidos).`;
                    strengthsList.appendChild(li);
                    strengthsCount++;
                } else {
                    const li = document.createElement('li');
                    li.innerHTML = `<strong>${catNamesFriendly[cat]}:</strong> Progresso de ${stats.pct}% (${stats.solved}/${stats.total} resolvidos). Foco recomendado!`;
                    weaknessesList.appendChild(li);
                    weaknessesCount++;
                }
            });

            if (strengthsCount === 0) {
                strengthsList.innerHTML = '<li>Nenhuma categoria com domínio >= 50% ainda. Continue resolvendo desafios!</li>';
            }
            if (weaknessesCount === 0) {
                weaknessesList.innerHTML = '<li>Parabéns! Todas as categorias possuem mais de 50% de domínio.</li>';
            }
        }
    };

    // --- CARREGAR PROGRESSO SALVO ---
    const loadProgress = () => {
        const savedSolved = localStorage.getItem('netscan_solved_100_challenges');
        const savedHints = localStorage.getItem('netscan_used_100_hints');
        const savedAnswers = localStorage.getItem('netscan_solved_100_answers');
        
        if (savedSolved) {
            try {
                state.solvedChallenges = JSON.parse(savedSolved);
            } catch (e) {
                state.solvedChallenges = [];
            }
        }
        if (savedHints) {
            try {
                state.usedHints = JSON.parse(savedHints);
                state.hintsUsedCount = state.usedHints.length;
            } catch (e) {
                state.usedHints = [];
                state.hintsUsedCount = 0;
            }
        }
        if (savedAnswers) {
            try {
                state.solvedAnswers = JSON.parse(savedAnswers);
            } catch (e) {
                state.solvedAnswers = {};
            }
        }
        
        updateChallengesUI();
        updateProgressWidget();
        updatePerformanceUI();
        updateHintsCountUI();
    };

    // --- SALVAR PROGRESSO ---
    const saveProgress = (id, answer) => {
        if (!state.solvedChallenges.includes(id)) {
            state.solvedChallenges.push(id);
        }
        if (answer) {
            state.solvedAnswers[id] = answer;
        }
        localStorage.setItem('netscan_solved_100_challenges', JSON.stringify(state.solvedChallenges));
        localStorage.setItem('netscan_solved_100_answers', JSON.stringify(state.solvedAnswers));
        
        updateChallengesUI();
        updateProgressWidget();
        updatePerformanceUI();
        updateHintsCountUI();
    };

    // --- NAVEGAÇÃO DE ABAS GERAIS ---
    const navButtons = document.querySelectorAll('.nav-btn');
    const contentPanes = document.querySelectorAll('.content-pane');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');
            
            navButtons.forEach(b => b.classList.remove('active'));
            contentPanes.forEach(p => p.classList.remove('active'));
            
            btn.classList.add('active');
            const pane = document.getElementById(`pane-${target}`);
            if (pane) pane.classList.add('active');
            
            if (target === 'desempenho') {
                updatePerformanceUI();
            }
        });
    });

    // --- NAVEGAÇÃO DE SUB-ABAS DA TEORIA ---
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const content = document.getElementById(tabId);
            if (content) content.classList.add('active');
        });
    });

    // --- VERIFICADOR DE STATUS DO LAB E FIREWALL ---
    const checkLabStatus = async () => {
        try {
            const res = await fetch('/api/status');
            if (res.ok) {
                const data = await res.json();
                
                // Atualizar Header
                const privilegeVal = document.querySelector('#status-privilege .value');
                const snifferVal = document.querySelector('#status-sniffer .value');
                
                if (data.running_as_root) {
                    privilegeVal.textContent = "ROOT (Sudo)";
                    privilegeVal.className = "value text-success";
                    snifferVal.textContent = "ATIVO";
                    snifferVal.className = "value text-success";
                } else {
                    privilegeVal.textContent = "Usuário Comum";
                    privilegeVal.className = "value text-warning";
                    snifferVal.textContent = "INATIVO";
                    snifferVal.className = "value text-danger";
                }

                // Sincronizar estado do firewall
                state.firewallActive = data.firewall_active;
                const fwToggle = document.getElementById('firewall-toggle');
                const fwStatus = document.getElementById('firewall-status');
                
                fwToggle.checked = state.firewallActive;
                if (state.firewallActive) {
                    fwStatus.textContent = "ATIVO (Bloqueando)";
                    fwStatus.className = "firewall-status-label text-success";
                } else {
                    fwStatus.textContent = "INATIVO";
                    fwStatus.className = "firewall-status-label text-danger";
                }
            }
        } catch (e) {
            console.error("Erro ao obter status do lab:", e);
        }
    };

    // --- CONTROLAR FIREWALL ---
    document.getElementById('firewall-toggle').addEventListener('change', async (e) => {
        const active = e.target.checked;
        try {
            const res = await fetch('/api/toggle-firewall', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ active: active })
            });
            if (res.ok) {
                const data = await res.json();
                state.firewallActive = data.firewall_active;
                const fwStatus = document.getElementById('firewall-status');
                if (state.firewallActive) {
                    fwStatus.textContent = "ATIVO (Bloqueando)";
                    fwStatus.className = "firewall-status-label text-success";
                } else {
                    fwStatus.textContent = "INATIVO";
                    fwStatus.className = "firewall-status-label text-danger";
                }
            }
        } catch (err) {
            console.error("Erro ao alternar firewall:", err);
            e.target.checked = !active; // reverte estado
        }
    });

    // --- LÓGICA DE UNLOCKS DE DESAFIOS ---
    const isUnlocked = (ch) => {
        const categoryChs = ALL_CHALLENGES.filter(c => c.category === ch.category);
        const idx = categoryChs.findIndex(c => c.id === ch.id);
        if (idx === 0) return true; // Primeiro de cada categoria está sempre liberado
        const prevCh = categoryChs[idx - 1];
        return state.solvedChallenges.includes(prevCh.id);
    };

    // --- INTERFACE DE DESAFIOS DINÂMICOS (CTF) ---
    const challengesContainer = document.getElementById('challenges-container');

    const updateChallengesUI = () => {
        // Salvar qual ID estava expandido para mantê-lo assim
        const expandedId = document.querySelector('.challenge-card.expanded')?.id;
        
        challengesContainer.innerHTML = '';
        
        // Mapeamento de nomes de Categorias
        const categoryNames = {
            'nmap': "Nmap (Varredura Ativa)",
            'netcat': "Netcat (Conexão e Portas)",
            'wireshark': "Wireshark (Análise L4)",
            'ffuf': "Ffuf & Gobuster (Fuzzing Web)"
        };

        const categories = ['nmap', 'netcat', 'wireshark', 'ffuf'];

        categories.forEach(cat => {
            // Verificar se o filtro selecionado corresponde a esta categoria
            if (state.activeModuleFilter !== 'all' && state.activeModuleFilter !== cat) {
                return;
            }

            // Filtrar desafios da categoria
            let challenges = ALL_CHALLENGES.filter(c => c.category === cat);

            // Filtrar por Dificuldade
            if (state.activeDifficultyFilter !== 'all') {
                challenges = challenges.filter(c => c.difficulty === state.activeDifficultyFilter);
            }

            // Filtrar por busca (pesquisa textual por ID ou título)
            if (state.searchQuery) {
                const query = state.searchQuery.toLowerCase();
                challenges = challenges.filter(c => 
                    c.id.toString() === query || 
                    c.title.toLowerCase().includes(query) || 
                    c.desc.toLowerCase().includes(query)
                );
            }

            if (challenges.length === 0) return;

            // Header da Categoria
            const moduleHeader = document.createElement('h3');
            moduleHeader.className = 'challenge-module-header';
            moduleHeader.textContent = categoryNames[cat];
            challengesContainer.appendChild(moduleHeader);

            // Renderizar cada card da categoria
            challenges.forEach(ch => {
                const isSolved = state.solvedChallenges.includes(ch.id);
                const unlocked = isUnlocked(ch);
                
                const card = document.createElement('div');
                card.className = `challenge-card ${isSolved ? 'solved-state' : unlocked ? 'unlocked-state' : 'locked-state'}`;
                if (expandedId === `challenge-${ch.id}`) {
                    card.classList.add('expanded');
                }
                card.id = `challenge-${ch.id}`;
                card.setAttribute('data-level', ch.id);

                let statusBadgeText = isSolved ? "Resolvido" : unlocked ? "Disponível" : "Bloqueado";
                const isHintUsed = state.usedHints.includes(ch.id);
                const displayPoints = isSolved && isHintUsed ? Math.round(ch.points * 0.9) : ch.points;

                card.innerHTML = `
                    <div class="challenge-header">
                        <span class="status-badge">${statusBadgeText}</span>
                        <h4>Desafio ${ch.id}: ${ch.title}</h4>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <span class="difficulty-badge difficulty-${ch.difficulty}">${ch.difficulty}</span>
                            <span class="points">${displayPoints} Pts</span>
                        </div>
                    </div>
                    <div class="challenge-body">
                        <p>${ch.desc}</p>
                        ${(ch.cmd && isSolved) ? `
                        <div class="code-copy">
                            <code>${ch.cmd}</code>
                        </div>
                        ` : ''}
                        
                        <div class="challenge-actions">
                            <button class="btn-action btn-help-trigger" data-id="${ch.id}">
                                ℹ️ Ajuda
                            </button>
                            <button class="btn-action btn-hint-trigger" data-id="${ch.id}" ${!unlocked ? 'disabled' : ''}>
                                💡 Dica ${isHintUsed ? '(Revelada)' : ''}
                            </button>
                        </div>

                        <div class="help-block" id="help-block-${ch.id}" style="display: none;">
                            <strong>Ajuda Pedagógica:</strong>
                            <p>${ch.help}</p>
                        </div>

                        <div class="hint-block" id="hint-block-${ch.id}" style="display: none;">
                            <strong>Dica do Instrutor:</strong>
                            <p>${ch.hint}</p>
                            <span class="warning-penalty">* -10% de penalidade aplicada ao placar final.</span>
                        </div>

                        <div class="flag-section">
                            <label for="input-flag-${ch.id}">Digite sua resposta ou FLAG:</label>
                            <div class="flag-input-group">
                                <input type="text" id="input-flag-${ch.id}" placeholder="Resposta..." value="${isSolved ? (state.solvedAnswers[ch.id] || OFFICIAL_ANSWERS[ch.id] || '') : ''}" ${!unlocked || isSolved ? 'disabled' : ''}>
                                <button class="btn btn-primary btn-submit-flag" data-id="${ch.id}" ${!unlocked || isSolved ? 'disabled' : ''}>Enviar</button>
                            </div>
                            <span class="feedback-msg" id="feedback-${ch.id}"></span>
                        </div>
                    </div>
                `;

                // Add Toggle expansion
                card.querySelector('.challenge-header').addEventListener('click', (e) => {
                    // Ignora cliques em botões
                    if (e.target.closest('.difficulty-badge') || e.target.closest('.points')) return;
                    
                    if (unlocked || isSolved) {
                        card.classList.toggle('expanded');
                    }
                });

                // Add Help click
                card.querySelector('.btn-help-trigger').addEventListener('click', () => {
                    const helpBlock = document.getElementById(`help-block-${ch.id}`);
                    helpBlock.style.display = helpBlock.style.display === 'none' ? 'block' : 'none';
                });

                // Add Hint click
                card.querySelector('.btn-hint-trigger').addEventListener('click', () => {
                    if (!unlocked) return;
                    revealHint(ch.id, ch.points);
                });

                // Add Submit flag
                card.querySelector('.btn-submit-flag').addEventListener('click', () => {
                    submitFlag(ch.id);
                });

                // Add Enter key listener to input
                const inputFieldEl = card.querySelector(`#input-flag-${ch.id}`);
                if (inputFieldEl) {
                    inputFieldEl.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            submitFlag(ch.id);
                        }
                    });
                }

                challengesContainer.appendChild(card);
            });
        });

        // Se nenhum desafio corresponder aos filtros
        if (challengesContainer.children.length === 0) {
            challengesContainer.innerHTML = '<div style="text-align:center; padding: 2rem; color: var(--color-text-muted);">Nenhum desafio corresponde aos filtros selecionados.</div>';
        }
    };

    // --- REVELAR DICA (COM CONFIRMAÇÃO E PENALIDADE) ---
    const revealHint = (id, points) => {
        const hintBlock = document.getElementById(`hint-block-${id}`);
        const ch = ALL_CHALLENGES.find(c => c.id === id);
        if (!ch) return;
        
        // Se a dica já foi usada anteriormente para este desafio, apenas exibe
        if (state.usedHints.includes(id)) {
            hintBlock.style.display = hintBlock.style.display === 'none' ? 'block' : 'none';
            return;
        }

        // Verifica limite de dicas na categoria do desafio
        const categoryHintsCount = getCategoryHintsCount(ch.category);
        if (categoryHintsCount >= 5) {
            alert(`Limite máximo de dicas atingido para a categoria ${ch.category.toUpperCase()}! Você só pode usar 5 dicas por categoria.`);
            return;
        }

        const confirmed = confirm(`Usar essa dica gastará 10% dos pontos (${Math.round(points * 0.1)} Pts) desse desafio e será contabilizado no seu limite de 5 dicas para a categoria ${ch.category.toUpperCase()}.\n\nConfirmar liberação?`);
        if (confirmed) {
            state.usedHints.push(id);
            localStorage.setItem('netscan_used_100_hints', JSON.stringify(state.usedHints));
            
            // Exibir a dica
            hintBlock.style.display = 'block';
            
            // Atualizar UI
            updateHintsCountUI();
            updateChallengesUI();
            updateProgressWidget();
            updatePerformanceUI();
        }
    };

    // --- SUBMETER RESPOSTA/FLAG ---
    const submitFlag = async (id) => {
        const inputField = document.getElementById(`input-flag-${id}`);
        const feedbackField = document.getElementById(`feedback-${id}`);
        const flag = inputField.value.trim();
        
        if (!flag) {
            feedbackField.textContent = "Por favor, digite uma resposta.";
            feedbackField.className = "feedback-msg error";
            return;
        }

        try {
            const res = await fetch('/api/submit-flag', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challenge_id: id, flag: flag })
            });
            
            if (res.ok) {
                const data = await res.json();
                if (data.success) {
                    feedbackField.textContent = data.message;
                    feedbackField.className = "feedback-msg success";
                    saveProgress(id, flag);
                } else {
                    feedbackField.textContent = data.message;
                    feedbackField.className = "feedback-msg error";
                }
            } else {
                feedbackField.textContent = "Erro de conexão com o servidor.";
                feedbackField.className = "feedback-msg error";
            }
        } catch (e) {
            feedbackField.textContent = "Erro interno.";
            feedbackField.className = "feedback-msg error";
        }
    };

    // --- ATUALIZAR FILTROS ---
    document.getElementById('filter-module').addEventListener('change', (e) => {
        state.activeModuleFilter = e.target.value;
        updateChallengesUI();
        updateHintsCountUI();
    });

    document.getElementById('filter-difficulty').addEventListener('change', (e) => {
        state.activeDifficultyFilter = e.target.value;
        updateChallengesUI();
    });

    document.getElementById('search-challenge').addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        updateChallengesUI();
    });

    // --- RESETAR PROGRESSO ---
    document.getElementById('btn-reset-ctf').addEventListener('click', () => {
        if (confirm("Deseja realmente resetar todo o progresso do laboratório? Isso apagará todas as suas respostas e dicas usadas.")) {
            state.solvedChallenges = [];
            state.solvedAnswers = {};
            state.usedHints = [];
            state.hintsUsedCount = 0;
            
            localStorage.removeItem('netscan_solved_100_challenges');
            localStorage.removeItem('netscan_solved_100_answers');
            localStorage.removeItem('netscan_used_100_hints');
            
            updateChallengesUI();
            updateProgressWidget();
            updatePerformanceUI();
            updateHintsCountUI();
        }
    });

    // --- PROGRESSO E SCORE WIDGETS ---
    const updateProgressWidget = () => {
        const solvedCount = state.solvedChallenges.length;
        const total = ALL_CHALLENGES.length;
        const pct = (solvedCount / total) * 100;
        
        document.getElementById('progress-fill').style.width = `${pct}%`;
        document.getElementById('progress-percent').textContent = `${Math.round(pct)}% Concluído`;
        document.getElementById('progress-fraction').textContent = `${solvedCount}/${total} Resolvidos`;
        
        document.getElementById('stats-completed').textContent = `${solvedCount}/${total}`;
        document.getElementById('stats-score').textContent = calculateTotalScore();
        updateHintsCountUI();
    };

    // --- CONSOLE DO IDS (SSE LIVE FEED) ---
    const logsContainer = document.getElementById('ids-logs-container');
    const scansCountEl = document.getElementById('stats-scans-count');
    const stealthCountEl = document.getElementById('stats-stealth-count');
    
    state.idsLogsList = [];

    const renderIDSLogs = () => {
        const filterVal = document.getElementById('ids-filter-select').value;
        logsContainer.innerHTML = '';
        
        const filtered = state.idsLogsList.filter(log => {
            if (filterVal === 'all') return true;
            if (filterVal === 'alerts') {
                const desc = log.description.toUpperCase();
                return desc.includes('STEALTH') || desc.includes('EVASAO') || desc.includes('EVASÃO') || desc.includes('BYPASS');
            }
            if (filterVal === 'blocked') {
                return log.description.toUpperCase().includes('BLOQUEADO');
            }
            if (filterVal === 'ftp') {
                return log.dst_port === 9001;
            }
            if (filterVal === 'custom_ports') {
                const p = log.dst_port;
                return p === 9002 || p === 9003 || p === 9004 || p === 9006 || p === 9008 || p === 9009 || p === 9110 || p === 9143 || p === 9555;
            }
            return true;
        });

        if (filtered.length === 0) {
            logsContainer.innerHTML = '<div class="empty-logs">Nenhum log corresponde ao filtro selecionado...</div>';
            return;
        }

        filtered.forEach(log => {
            const row = document.createElement('div');
            row.className = 'log-row';
            if (log.description.includes('BYPASS SUCESSO')) {
                row.style.background = 'rgba(0, 229, 153, 0.1)';
                row.style.borderLeft = '4px solid #00e599';
            } else if (log.description.includes('BLOQUEADO')) {
                row.style.background = 'rgba(255, 75, 75, 0.1)';
                row.style.borderLeft = '4px solid #ff4b4b';
            }
            
            let flagClass = '';
            if (log.flags.includes('SYN')) flagClass = 'badge-flag-syn';
            if (log.flags.includes('RST')) flagClass = 'badge-flag-rst';
            if (log.flags.includes('Xmas') || log.flags.includes('FIN+PSH+URG')) flagClass = 'badge-flag-xmas';
            if (log.flags.includes('NULL')) flagClass = 'badge-flag-null';

            row.innerHTML = `
                <div class="col-time">${log.timestamp}</div>
                <div class="col-origem">${log.src_ip}:${log.src_port}</div>
                <div class="col-destino">${log.dst_ip}:${log.dst_port}</div>
                <div class="col-flags ${flagClass}">${log.flags}</div>
                <div class="col-desc">${log.description}</div>
            `;
            
            row.addEventListener('click', () => {
                const existingDetails = row.nextElementSibling;
                if (existingDetails && existingDetails.classList.contains('log-details')) {
                    existingDetails.remove();
                } else {
                    const details = document.createElement('div');
                    details.className = 'log-details';
                    details.innerHTML = `
                        <span><strong>Nº Seqüência (SEQ):</strong> ${log.seq}</span>
                        <span><strong>Nº Confirmação (ACK):</strong> ${log.ack}</span>
                        <span><strong>Destino:</strong> localhost / 127.0.0.1</span>
                        <span><strong>Status:</strong> Filtro de IDS de Rede Concluído</span>
                    `;
                    row.after(details);
                }
            });
            
            logsContainer.appendChild(row);
        });
    };

    const initSSE = () => {
        state.eventSource = new EventSource('/api/ids-logs');
        
        state.eventSource.onmessage = (event) => {
            if (state.idsLogsPaused) return;
            
            try {
                const log = JSON.parse(event.data);
                
                state.scansCount++;
                scansCountEl.textContent = state.scansCount;
                
                if (log.description.includes('Stealth') || log.description.includes('Evasão') || log.description.includes('BYPASS')) {
                    state.stealthCount++;
                    stealthCountEl.textContent = state.stealthCount;
                }

                state.idsLogsList.unshift(log);
                if (state.idsLogsList.length > 100) {
                    state.idsLogsList.pop();
                }
                
                renderIDSLogs();
                
            } catch (e) {
                console.error("Erro ao tratar mensagem de log do IDS:", e);
            }
        };

        state.eventSource.onerror = (e) => {
            console.error("Conexão SSE perdida. Tentando reconectar...");
            state.eventSource.close();
            setTimeout(initSSE, 3000);
        };
    };

    document.getElementById('ids-filter-select').addEventListener('change', renderIDSLogs);

    // Controles do IDS Console
    document.getElementById('btn-clear-logs').addEventListener('click', () => {
        state.idsLogsList = [];
        logsContainer.innerHTML = '<div class="empty-logs">Console limpo. Aguardando novo tráfego...</div>';
        state.scansCount = 0;
        state.stealthCount = 0;
        scansCountEl.textContent = '0';
        stealthCountEl.textContent = '0';
    });

    const pauseBtn = document.getElementById('btn-pause-logs');
    pauseBtn.addEventListener('click', () => {
        state.idsLogsPaused = !state.idsLogsPaused;
        if (state.idsLogsPaused) {
            pauseBtn.textContent = "Retomar Captura";
            document.getElementById('ids-status-dot').className = "pulse-indicator-small red-glow";
            document.getElementById('ids-status-text').textContent = "Captura Pausada";
        } else {
            pauseBtn.textContent = "Pausar Captura";
            document.getElementById('ids-status-dot').className = "pulse-indicator-small";
            document.getElementById('ids-status-text').textContent = "Escutando loops de rede local...";
            renderIDSLogs();
        }
    });

    // --- SIMULADOR VISUAL DE HANDSHAKE TCP ---
    const simSvg = document.getElementById('sim-svg');
    const simExplanation = document.getElementById('sim-explanation');
    const simBtns = document.querySelectorAll('.sim-btn');
    let simTimeoutId = null;

    const clearSimulation = () => {
        if (simTimeoutId) clearTimeout(simTimeoutId);
        simSvg.innerHTML = '';
        simExplanation.textContent = 'Selecione um método acima para iniciar a simulação visual quadro a quadro.';
    };

    const drawLine = (fromX, toX, y, label, colorClass, delay, duration) => {
        return new Promise((resolve) => {
            simTimeoutId = setTimeout(() => {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", fromX);
                line.setAttribute("y1", y);
                line.setAttribute("x2", fromX);
                line.setAttribute("y2", y);
                line.setAttribute("stroke", colorClass === 'blue' ? '#00ccff' : colorClass === 'green' ? '#00ff66' : colorClass === 'purple' ? '#9d4edd' : '#ff3366');
                line.setAttribute("stroke-width", "2");
                
                const animateX2 = document.createElementNS("http://www.w3.org/2000/svg", "animate");
                animateX2.setAttribute("attributeName", "x2");
                animateX2.setAttribute("from", fromX);
                animateX2.setAttribute("to", toX);
                animateX2.setAttribute("dur", `${duration}s`);
                animateX2.setAttribute("fill", "freeze");
                line.appendChild(animateX2);
                
                const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                text.setAttribute("x", (fromX + toX) / 2);
                text.setAttribute("y", y - 6);
                text.setAttribute("text-anchor", "middle");
                text.setAttribute("fill", "#fff");
                text.setAttribute("font-size", "10");
                text.setAttribute("font-family", "var(--font-mono)");
                text.textContent = label;
                text.style.opacity = '0';
                
                const animateOpacity = document.createElementNS("http://www.w3.org/2000/svg", "animate");
                animateOpacity.setAttribute("attributeName", "opacity");
                animateOpacity.setAttribute("from", "0");
                animateOpacity.setAttribute("to", "1");
                animateOpacity.setAttribute("dur", "0.2s");
                animateOpacity.setAttribute("fill", "freeze");
                text.appendChild(animateOpacity);

                simSvg.appendChild(line);
                simSvg.appendChild(text);
                
                setTimeout(resolve, duration * 1000 + 100);
            }, delay);
        });
    };

    const runSimulation = async (type) => {
        clearSimulation();
        
        simBtns.forEach(b => b.classList.remove('active'));
        const activeBtn = document.querySelector(`.sim-btn[data-scan="${type}"]`);
        if (activeBtn) activeBtn.classList.add('active');

        if (type === 'connect') {
            simExplanation.innerHTML = "<strong>Passo 1:</strong> Iniciando o 3-Way Handshake. O atacante envia o pacote TCP [SYN].";
            await drawLine(40, 360, 30, "SYN (Seq=0)", "blue", 0, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 2:</strong> A porta está Aberta. O Alvo responde com [SYN, ACK].";
            await drawLine(360, 40, 60, "SYN+ACK (Seq=0 Ack=1)", "green", 1800, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 3:</strong> Handshake Completo. O Atacante confirma com [ACK]. A conexão é registrada no kernel e na camada de aplicação.";
            await drawLine(40, 360, 90, "ACK (Seq=1 Ack=1)", "blue", 1800, 2.0);

            simExplanation.innerHTML = "<strong>Passo 4:</strong> Desconexão. O scanner fecha a conexão abruptamente com um [RST, ACK].";
            await drawLine(40, 360, 120, "RST+ACK", "red", 1800, 2.0);
            
        } else if (type === 'syn') {
            simExplanation.innerHTML = "<strong>Passo 1:</strong> Varredura Stealth. O atacante envia o probe TCP [SYN].";
            await drawLine(40, 360, 35, "SYN (Seq=0)", "blue", 0, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 2:</strong> Porta Aberta. O alvo envia o handshake [SYN, ACK].";
            await drawLine(360, 40, 75, "SYN+ACK (Seq=0 Ack=1)", "green", 1800, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 3:</strong> Abortando! O atacante envia um [RST] (Reset) imediatamente. A conexão é fechada antes do 3-way handshake concluir. Nenhum log gerado no app do alvo!";
            await drawLine(40, 360, 115, "RST (Seq=1)", "red", 1800, 2.0);
            
        } else if (type === 'xmas-open') {
            simExplanation.innerHTML = "<strong>Passo 1:</strong> Scan Inverso (Xmas). O atacante envia flags FIN, PSH e URG ativas juntas.";
            await drawLine(40, 360, 40, "FIN+PSH+URG", "purple", 0, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 2:</strong> Regra RFC 793 (Porta Aberta): O Alvo simplesmente descarta o pacote de forma silenciosa. O Nmap assume <em>open|filtered</em> devido à falta de resposta.";
            simTimeoutId = setTimeout(() => {
                const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                text.setAttribute("x", 200);
                text.setAttribute("y", 90);
                text.setAttribute("text-anchor", "middle");
                text.setAttribute("fill", "var(--color-text-muted)");
                text.setAttribute("font-size", "11");
                text.textContent = "[ Pacote Descartado Silenciosamente ]";
                simSvg.appendChild(text);
            }, 2500);
            
        } else if (type === 'xmas-closed') {
            simExplanation.innerHTML = "<strong>Passo 1:</strong> Scan Inverso. Envio de flags Xmas (FIN+PSH+URG) para porta fechada.";
            await drawLine(40, 360, 45, "FIN+PSH+URG", "purple", 0, 2.0);
            
            simExplanation.innerHTML = "<strong>Passo 2:</strong> Regra RFC 793 (Porta Fechada): O host Alvo rejeita o pacote enviando um [RST, ACK]. O Nmap sabe que a porta está fechada.";
            await drawLine(360, 40, 95, "RST+ACK", "red", 1800, 2.0);
        }
    };

    simBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const scanType = btn.getAttribute('data-scan');
            runSimulation(scanType);
        });
    });

    // --- INICIALIZADORES ---
    checkLabStatus();
    loadProgress();
    initSSE();

    // Roda verificação a cada 10 segundos
    setInterval(checkLabStatus, 10000);
});
