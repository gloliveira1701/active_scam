#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laboratório de Varredura Ativa, Enumeração Profunda e Análise de Tráfego de Rede.
Este script implementa:
1. Um servidor HTTP para o Dashboard e sistema de CTF (porta 80 ou 8080)
2. APIs de validação de desafios e logs do IDS via Server-Sent Events (SSE)
3. Um listener TCP na porta 9001 simulando um serviço FTP vulnerável
4. Um sniffer Raw Socket de pacotes TCP para análise em tempo real (necessita de sudo)
"""

import os
import sys
import json
import socket
import struct
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Configurações do Laboratório
PORT_WEB = int(os.environ.get('PORT_ENV', 80 if os.getuid() == 0 else 8080))
PORT_MOCK_FTP = 9001
PORT_MOCK_9002 = 9002
PORT_MOCK_SMTP = 9003
PORT_MOCK_TELNET = 9004
PORT_MOCK_MYSQL = 9006
PORT_MOCK_REDIS = 9008
PORT_MOCK_UDP = 9009
PORT_MOCK_POP3 = 9110
PORT_MOCK_IMAP = 9143
PORT_MOCK_HIGH = 9555
RUNNING_AS_ROOT = (os.getuid() == 0)
FIREWALL_ACTIVE = False

# Estrutura de armazenamento de logs e locks
ids_logs = []
logs_lock = threading.Lock()
clients_sse = []
clients_lock = threading.Lock()

def add_ids_log(log_entry):
    """Adiciona um log no IDS e notifica clientes conectados no SSE"""
    with logs_lock:
        ids_logs.append(log_entry)
        if len(ids_logs) > 200:
            ids_logs.pop(0)
    
    # Notificar clientes conectados via SSE
    with clients_lock:
        for queue in clients_sse:
            queue.append(log_entry)

# --- SNIFFER RAW SOCKET (IDS) ---
def start_raw_sniffer():
    """Inicia a captura e dissecação de pacotes TCP na interface local"""
    if not RUNNING_AS_ROOT:
        print("[*] Sniffer RAW desativado (não executado como root).")
        return

    try:
        # Sniffer captura pacotes TCP na rede
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print(f"[+] Sniffer IDS ativo em Raw Socket (capturando pacotes TCP)...")
    except Exception as e:
        print(f"[!] Falha ao iniciar Raw Sniffer: {e}")
        return

    while True:
        try:
            packet, addr = sniffer.recvfrom(65535)
            
            # Cabeçalho IP (primeiros 20 bytes)
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Ignorar pacotes que não sejam para loopback ou IPs de teste local
            if src_ip != "127.0.0.1" and dst_ip != "127.0.0.1":
                continue
                
            # Cabeçalho TCP (próximos 20 bytes)
            tcp_header = packet[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dst_port = tcph[1]
            
            # Descartar tráfego interno de depuração (Chrome DevTools / CDP / Live Reload)
            # Para evitar que as comunicações do navegador poluam o terminal e console do IDS
            if src_port in (9222, 9229) or dst_port in (9222, 9229):
                continue
                
            seq_num = tcph[2]
            ack_num = tcph[3]
            offset_reserved = tcph[4]
            flags = tcph[5]
            
            # Filtrar tráfego da própria dashboard para evitar feedback loop infinito
            # Ignoramos conexões HTTP estabelecidas do dashboard (porta 80/8080)
            if (src_port == PORT_WEB or dst_port == PORT_WEB) and not (flags & 0x02 or flags & 0x01 or flags & 0x04 or flags == 0):
                # Ignora se for tráfego HTTP normal (sem SYN, FIN, RST ou NULL)
                continue

            # Mapeamento de Flags TCP
            fin = flags & 0x01
            syn = flags & 0x02
            rst = flags & 0x04
            psh = flags & 0x08
            ack = flags & 0x10
            urg = flags & 0x20
            
            flags_list = []
            if syn: flags_list.append("SYN")
            if ack: flags_list.append("ACK")
            if fin: flags_list.append("FIN")
            if rst: flags_list.append("RST")
            if psh: flags_list.append("PSH")
            if urg: flags_list.append("URG")
            
            flags_label = "+".join(flags_list) if flags_list else "NULL (Nenhum)"
            
            # Análise heurística simplificada de assinaturas de varredura
            scan_desc = "Tráfego TCP Geral"
            
            if FIREWALL_ACTIVE and dst_port == PORT_MOCK_FTP:
                if flags == 0:
                    scan_desc = "BYPASS SUCESSO: NULL scan contornou o Firewall! Revelando Flag: FLAG{NULL_F1R3W4LL_BYP4SS}"
                elif flags_label == "FIN":
                    scan_desc = "BYPASS SUCESSO: FIN scan contornou o Firewall! Revelando Flag: FLAG{FIN_F1R3W4LL_BYP4SS}"
                elif flags_label == "FIN+PSH+URG":
                    scan_desc = "BYPASS SUCESSO: Xmas scan contornou o Firewall! Revelando Flag: FLAG{XM4S_F1R3W4LL_BYP4SS}"
                elif flags_label == "ACK":
                    scan_desc = "BYPASS SUCESSO: ACK scan detectado! Revelando Flag: FLAG{ACK_F1R3W4LL_BYP4SS}"
                elif flags_label == "SYN" and src_port == 53:
                    scan_desc = "BYPASS SUCESSO: Porta de origem confiável (53 - DNS) detectada! Revelando Flag: FLAG{SRCPORT_F1R3W4LL_BYP4SS}"
                elif flags_label == "SYN":
                    scan_desc = "BLOQUEADO: Varredura padrão detectada e bloqueada pelo Firewall!"
            else:
                # Evasão baseada em RFC
                if flags == 0:
                    scan_desc = "TCP NULL Scan (Evasão / Nmap -sN)"
                elif flags_label == "FIN":
                    scan_desc = "TCP FIN Scan (Evasão / Nmap -sF)"
                elif flags_label == "FIN+PSH+URG":
                    scan_desc = "TCP Xmas Scan (Evasão / Nmap -sX)"
                # Varreduras clássicas
                elif flags_label == "SYN":
                    if dst_port == PORT_MOCK_FTP:
                        scan_desc = "SYN Stealth Probe na porta FTP (Nmap -sS)"
                    elif dst_port == PORT_WEB:
                        scan_desc = "SYN Stealth Probe na porta Web (Nmap -sS)"
                    else:
                        scan_desc = f"SYN Stealth Probe na porta {dst_port} (Nmap -sS)"
                elif flags_label == "ACK":
                    scan_desc = "TCP ACK Scan (Auditoria de Firewall / Nmap -sA ou Hping3 -A)"
                elif flags_label == "SYN+ACK":
                    scan_desc = "Resposta SYN-ACK do Alvo (Porta Aberta)"
                elif flags_label == "RST" or flags_label == "RST+ACK":
                    scan_desc = "Resposta RST (Porta Fechada ou Conexão Abortada)"
                elif psh and ack:
                    if dst_port == PORT_WEB:
                        scan_desc = "Requisição HTTP ( ffuf ou Navegador )"
                    else:
                        scan_desc = "Envio de Dados TCP (PSH+ACK)"

            log_entry = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flags": flags_label,
                "seq": seq_num,
                "ack": ack_num,
                "description": scan_desc
            }
            
            add_ids_log(log_entry)
            
        except Exception:
            continue

# --- NOVOS SERVIÇOS SIMULADOS (DESAFIOS PRÁTICOS ADICIONAIS) ---

def handle_generic_firewall_and_bypass(conn, addr, port, custom_flag=""):
    """
    Função de conveniência para verificar se o firewall está ativo.
    Se ativo, apenas permite conexões originárias da porta 53 (DNS) e registra bypass.
    Se não for da porta 53, fecha a conexão e retorna False (bloqueado).
    """
    if FIREWALL_ACTIVE:
        if addr[1] == 53:
            # Bypass do firewall
            desc_alert = f"BYPASS SUCESSO: Conexão via porta de origem 53 (DNS) contornou o Firewall na porta {port}!"
            if custom_flag:
                desc_alert += f" Revelando Flag: {custom_flag}"
            add_ids_log({
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": addr[0],
                "src_port": addr[1],
                "dst_ip": "127.0.0.1",
                "dst_port": port,
                "flags": "SYN+ACK+ACK (Bypass)",
                "seq": 0,
                "ack": 0,
                "description": desc_alert
            })
            return True
        else:
            # Bloqueio do firewall
            add_ids_log({
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": addr[0],
                "src_port": addr[1],
                "dst_ip": "127.0.0.1",
                "dst_port": port,
                "flags": "DROP (Bloqueado)",
                "seq": 0,
                "ack": 0,
                "description": f"BLOQUEADO: Conexão na porta {port} bloqueada pelo Firewall!"
            })
            conn.close()
            return False
    return True

def start_mock_9002():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_9002))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar mock port 9002: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_9002):
                continue
            
            # Enviar banner
            conn.sendall(b"FLAG{NC_WELCOME_9002} Version: v1.0.0\n")
            
            # Ler dados interativos
            conn.settimeout(5.0)
            data = conn.recv(1024)
            if data:
                text = data.decode('utf-8', errors='ignore').strip()
                if "banana" in text:
                    conn.sendall(b"FLAG{NC_BANANA_OK}\n")
            conn.close()
        except Exception:
            pass

def start_mock_smtp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_SMTP))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar SMTP mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_SMTP):
                continue
            
            conn.sendall(b"220 SMTP Mock Server Ready\r\n")
            conn.settimeout(5.0)
            rfile = conn.makefile('r', encoding='utf-8', errors='ignore')
            for line in rfile:
                cmd = line.strip()
                if not cmd:
                    continue
                if cmd.upper().startswith("HELO") or cmd.upper().startswith("EHLO"):
                    conn.sendall(b"250 Hello\r\n")
                elif cmd.upper().startswith("VRFY ADMIN"):
                    conn.sendall(b"250 FLAG{SMTP_USER_ENUM_SUCCESS}\r\n")
                elif cmd.upper().startswith("QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"500 Command unrecognized\r\n")
            rfile.close()
            conn.close()
        except Exception:
            pass

def start_mock_telnet():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_TELNET))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar Telnet mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_TELNET, "FLAG{TELNET_LOGIN_BYPASS}"):
                continue
            
            conn.sendall(b"Username:\r\n")
            conn.settimeout(5.0)
            user = conn.recv(1024).decode('utf-8', errors='ignore').strip()
            conn.sendall(b"Password:\r\n")
            password = conn.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if user == "admin" and password == "admin":
                conn.sendall(b"Access granted.\r\nFLAG{TELNET_LOGIN_BYPASS}\r\n")
            else:
                conn.sendall(b"Login incorrect\r\n")
            conn.close()
        except Exception:
            pass

def start_mock_mysql():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_MYSQL))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar MySQL mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_MYSQL):
                continue
            
            # Enviar MySQL handshake binário contendo a flag
            handshake = b"\x4a\x00\x00\x00\x0a" + b"5.7.99-MariaDB-Flag-MySQL\x00" + b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"FLAG{MYSQL_BANNER_EXPOSED}\x00"
            conn.sendall(handshake)
            conn.close()
        except Exception:
            pass

def start_mock_redis():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_REDIS))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar Redis mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_REDIS):
                continue
            
            conn.settimeout(5.0)
            rfile = conn.makefile('r', encoding='utf-8', errors='ignore')
            for line in rfile:
                cmd = line.strip()
                if not cmd:
                    continue
                if "PING" in cmd.upper():
                    conn.sendall(b"+PONG\r\n")
                elif "GET FLAG" in cmd.upper():
                    conn.sendall(b"$28\r\nFLAG{REDIS_GET_FLAG_SUCCESS}\r\n")
                elif "QUIT" in cmd.upper():
                    break
                else:
                    conn.sendall(b"-ERR unknown command\r\n")
            rfile.close()
            conn.close()
        except Exception:
            pass

def start_mock_udp():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_UDP))
    except Exception as e:
        print(f"[!] Erro ao iniciar UDP mock na porta 9009: {e}")
        return

    while True:
        try:
            data, addr = server.recvfrom(1024)
            server.sendto(b"UDP Mock Server Ready (Port 9009 Open)", addr)
        except Exception:
            pass

def start_mock_pop3():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_POP3))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar POP3 mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_POP3):
                continue
            
            conn.sendall(b"+OK POP3 Server Ready\r\n")
            conn.settimeout(5.0)
            rfile = conn.makefile('r', encoding='utf-8', errors='ignore')
            user_ok = False
            for line in rfile:
                cmd = line.strip()
                if not cmd:
                    continue
                if cmd.upper().startswith("USER ADMIN"):
                    conn.sendall(b"+OK Welcome admin\r\n")
                    user_ok = True
                elif cmd.upper().startswith("PASS ADMIN"):
                    if user_ok:
                        conn.sendall(b"+OK Logged in.\r\nFLAG{POP3_LOGIN_SUCCESS}\r\n")
                    else:
                        conn.sendall(b"-ERR Need USER first\r\n")
                elif cmd.upper().startswith("QUIT"):
                    conn.sendall(b"+OK Bye\r\n")
                    break
                else:
                    conn.sendall(b"-ERR Command unrecognized\r\n")
            rfile.close()
            conn.close()
        except Exception:
            pass

def start_mock_imap():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_IMAP))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar IMAP mock: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_IMAP):
                continue
            
            conn.sendall(b"* OK IMAP Server Ready\r\n")
            conn.settimeout(5.0)
            rfile = conn.makefile('r', encoding='utf-8', errors='ignore')
            for line in rfile:
                cmd = line.strip()
                if not cmd:
                    continue
                if "LOGIN ADMIN ADMIN" in cmd.upper():
                    parts = cmd.split()
                    tag = parts[0] if parts else "A1"
                    conn.sendall(f"{tag} OK FLAG{{IMAP_LOGIN_SUCCESS}}\r\n".encode('utf-8'))
                elif "LOGOUT" in cmd.upper():
                    parts = cmd.split()
                    tag = parts[0] if parts else "A1"
                    conn.sendall(f"* BYE\r\n{tag} OK Logout completed\r\n".encode('utf-8'))
                    break
                else:
                    parts = cmd.split()
                    tag = parts[0] if parts else "A1"
                    conn.sendall(f"{tag} BAD Command unrecognized\r\n".encode('utf-8'))
            rfile.close()
            conn.close()
        except Exception:
            pass

def start_mock_high():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_HIGH))
        server.listen(10)
    except Exception as e:
        print(f"[!] Erro ao iniciar mock port 9555: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            if not handle_generic_firewall_and_bypass(conn, addr, PORT_MOCK_HIGH):
                continue
            conn.sendall(b"FLAG{HIGH_PORT_9555_FOUND}\n")
            conn.close()
        except Exception:
            pass

# --- SERVIÇO SIMULADO PORTA 9001 (FTP) ---
def start_mock_ftp():
    """Inicia um servidor TCP simples que emula um FTP contendo uma Flag no banner"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', PORT_MOCK_FTP))
        server.listen(10)
        print(f"[+] Serviço FTP simulado escutando em 127.0.0.1:{PORT_MOCK_FTP}")
    except Exception as e:
        print(f"[!] Erro ao iniciar FTP simulado na porta {PORT_MOCK_FTP}: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            
            if FIREWALL_ACTIVE:
                if addr[1] == 53:
                    # Bypass via source-port
                    banner = (
                        "220-FTP Server Alpha (Firewall Bypass Detectado!)\r\n"
                        "220-Porta de origem confiavel (53 - DNS) detectada.\r\n"
                        "220 FLAG{SRCPORT_F1R3W4LL_BYP4SS}\r\n"
                    )
                    conn.sendall(banner.encode('utf-8'))
                    conn.close()
                    
                    # Registrar log de bypass
                    add_ids_log({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "dst_ip": "127.0.0.1",
                        "dst_port": PORT_MOCK_FTP,
                        "flags": "SYN+ACK+ACK (Bypass)",
                        "seq": 0,
                        "ack": 0,
                        "description": "BYPASS SUCESSO: Conexão via porta 53 (DNS) contornou o Firewall!"
                    })
                    continue
                else:
                    # Conexão bloqueada pelo firewall
                    conn.close()
                    
                    # Registrar log de bloqueio
                    add_ids_log({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "dst_ip": "127.0.0.1",
                        "dst_port": PORT_MOCK_FTP,
                        "flags": "SYN",
                        "seq": 0,
                        "ack": 0,
                        "description": "BLOQUEADO: Conexão padrão bloqueada pelo Firewall!"
                    })
                    continue

            # Se for executado sem sniffer raw, ainda geramos log da conexão
            if not RUNNING_AS_ROOT:
                add_ids_log({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "src_ip": addr[0],
                    "src_port": addr[1],
                    "dst_ip": "127.0.0.1",
                    "dst_port": PORT_MOCK_FTP,
                    "flags": "SYN+ACK+ACK (Estabelecida)",
                    "seq": 0,
                    "ack": 0,
                    "description": "Conexão Completa via Porta 9001 (TCP Connect)"
                })
            
            # Envia o banner simulado com a Flag do Desafio 2
            banner = (
                "220-FTP Server Alpha (ProFTPD 1.3.5 Simulado)\r\n"
                "220-Seja bem-vindo ao servidor de testes pedagógicos.\r\n"
                "220 FLAG{B4NN3R_GR4BB1NG_SUCC3SS}\r\n"
            )
            conn.sendall(banner.encode('utf-8'))
            conn.close()
        except Exception:
            pass

# --- SERVIDOR WEB DA DASHBOARD E APIs (PORTA 80) ---
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP multi-threaded para suportar Server-Sent Events (SSE) sem bloquear"""
    daemon_threads = True

class LabHTTPHandler(BaseHTTPRequestHandler):
    """Handler das requisições HTTP do Dashboard, APIs de validação e Fuzzing"""
    
    # Silencia logs normais de console para não poluir o terminal
    def log_message(self, format, *args):
        pass

    def send_cors_headers(self):
        """Adiciona cabeçalhos CORS necessários"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        # 1. Endpoint Server-Sent Events (SSE) do IDS
        if self.path == '/api/ids-logs':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_cors_headers()
            self.end_headers()
            
            # Fila de mensagens local para esta conexão SSE
            my_queue = []
            with clients_lock:
                clients_sse.append(my_queue)
                
            try:
                # Envia o histórico existente ao conectar
                with logs_lock:
                    for log in ids_logs:
                        self.wfile.write(f"data: {json.dumps(log)}\n\n".encode('utf-8'))
                    self.wfile.flush()
                
                # Loop mantendo o canal aberto e transmitindo novos eventos
                while True:
                    if my_queue:
                        while my_queue:
                            log = my_queue.pop(0)
                            self.wfile.write(f"data: {json.dumps(log)}\n\n".encode('utf-8'))
                        self.wfile.flush()
                    time.sleep(0.1)
            except Exception:
                pass
            finally:
                with clients_lock:
                    if my_queue in clients_sse:
                        clients_sse.remove(my_queue)
            return

        # 2. Endpoint Fuzzing L7 - API Secreta (Desafio 4)
        elif self.path == '/api/v1/auth.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            
            data = {
                "status": "online",
                "db_endpoint": "10.0.0.50:5432",
                "jwt_secret": "sup3r_s3cr3t",
                "flag": "FLAG{Fuzz1ng_AP1_F0und}"
            }
            self.wfile.write(json.dumps(data).encode('utf-8'))
            
            # Registra log de auditoria no IDS
            add_ids_log({
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": self.client_address[0],
                "src_port": self.client_address[1],
                "dst_ip": "127.0.0.1",
                "dst_port": PORT_WEB,
                "flags": "HTTP GET",
                "seq": 0,
                "ack": 0,
                "description": "Alerta de Enumeração: Acesso a API restrita (/api/v1/auth.json)"
            })
            return

        # 3. Endpoint Fuzzing L7 - Backup SQL exposto (Desafio 4)
        elif self.path == '/backup_conf/database.sql':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_cors_headers()
            self.end_headers()
            
            sql_dump = (
                "-- Backup dump de banco de dados do sistema legado\n"
                "-- Gerado automaticamente pelo utilitário pg_dump\n"
                "-- Data de exportação: 2026-08-26\n\n"
                "CREATE TABLE IF NOT EXISTS users (\n"
                "    id INT PRIMARY KEY,\n"
                "    username VARCHAR(50),\n"
                "    password_hash VARCHAR(64)\n"
                ");\n\n"
                "INSERT INTO users (id, username, password_hash) VALUES\n"
                "(1, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997'),\n"
                "(2, 'flag_holder', 'FLAG{D4T4B4S3_DUMP_EXPOSED}');\n"
            )
            self.wfile.write(sql_dump.encode('utf-8'))
            
            # Registra log de auditoria no IDS
            add_ids_log({
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": self.client_address[0],
                "src_port": self.client_address[1],
                "dst_ip": "127.0.0.1",
                "dst_port": PORT_WEB,
                "flags": "HTTP GET",
                "seq": 0,
                "ack": 0,
                "description": "Alerta de Enumeração: Download de backup exposto (/backup_conf/database.sql)"
            })
            return

        # 4. Status do Laboratório
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            
            status = {
                "running_as_root": RUNNING_AS_ROOT,
                "port_web": PORT_WEB,
                "port_ftp": PORT_MOCK_FTP,
                "sniffer_active": RUNNING_AS_ROOT,
                "firewall_active": FIREWALL_ACTIVE
            }
            self.wfile.write(json.dumps(status).encode('utf-8'))
            return

        elif self.path == '/cookie-flag':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Set-Cookie', 'flag=FLAG{COOKIE_EXPOSED_OK}')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(b"FLAG{HTTP_COOKIE_CHECK}\n")
            return

        elif self.path == '/agent-flag':
            ua = self.headers.get('User-Agent', '')
            if ua == 'admin-browser':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"FLAG{USER_AGENT_ADMIN}\n")
            else:
                self.send_response(403)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"Access Denied. User-Agent invalid.\n")
            return

        elif self.path == '/session-flag':
            cookie = self.headers.get('Cookie', '')
            if 'session=admin' in cookie:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"FLAG{COOKIE_ADMIN}\n")
            else:
                self.send_response(403)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"Access Denied. Session invalid.\n")
            return

        # Novos endpoints de Netcat e Ffuf
        ffuf_endpoints = {
            '/nc-flag': ("text/plain", "FLAG{NC_GET_REQUEST_OK}"),
            '/secret-area/flag.txt': ("text/plain", "FLAG{FFUF_SECRET_AREA_FOUND}"),
            '/vulnerable/login.php': ("text/html", "FLAG{FFUF_LOGIN_PATH_DISCOVERED}"),
            '/backup.sql': ("text/plain", "FLAG{FFUF_DATABASE_BACKUP_EXPOSED}"),
            '/uploads/shell.php': ("text/html", "FLAG{FFUF_WEBSHELL_UPLOADED}"),
            '/dev/config.json': ("application/json", "FLAG{FFUF_DEV_CONFIG_LEAK}"),
            '/admin/logs.txt': ("text/plain", "FLAG{FFUF_ADMIN_LOGS_ACCESSIBLE}"),
            '/api/v1/users': ("application/json", "FLAG{FFUF_API_USERS_EXPOSED}"),
            '/tmp/session.db': ("application/octet-stream", "FLAG{FFUF_SESSION_DB_FOUND}"),
            '/assets/js/main.js.bak': ("application/javascript", "FLAG{FFUF_JS_BACKUP_LEAK}"),
            '/docs/internal_rules.pdf': ("application/pdf", "FLAG{FFUF_INTERNAL_DOCS}"),
            '/info.php': ("text/html", "FLAG{FFUF_INFO_PHP_EXPOSED}"),
            '/server-status': ("text/html", "FLAG{FFUF_SERVER_STATUS_VIEW}"),
            '/.git/config': ("text/plain", "FLAG{FFUF_GIT_CONFIG_LEAK}"),
            '/robots.txt': ("text/plain", "FLAG{FFUF_ROBOTS_TXT_FOUND}"),
            '/wp-config.php': ("text/plain", "FLAG{FFUF_WP_CONFIG_LEAK}"),
            '/phpmyadmin/index.php': ("text/html", "FLAG{FFUF_PHPMYADMIN_FOUND}"),
            '/test.cgi': ("text/plain", "FLAG{FFUF_CGI_TEST_EXPOSED}"),
            '/.env': ("text/plain", "FLAG{FFUF_ENV_FILE_LEAK}"),
            '/node_modules/': ("text/html", "FLAG{FFUF_NODE_MODULES_EXPOSED}"),
            '/node_modules': ("text/html", "FLAG{FFUF_NODE_MODULES_EXPOSED}"),
            '/console': ("text/html", "FLAG{FFUF_DEVELOPER_CONSOLE_LEAK}")
        }
        
        if self.path in ffuf_endpoints:
            content_type, flag = ffuf_endpoints[self.path]
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(flag.encode('utf-8'))
            return

        # 5. Servir Arquivos Estáticos (HTML, CSS, JS)
        else:
            filename = self.path.lstrip('/')
            if filename == '' or filename == 'index.html':
                filepath = 'index.html'
                content_type = 'text/html; charset=utf-8'
            elif filename == 'style.css':
                filepath = 'style.css'
                content_type = 'text/css; charset=utf-8'
            elif filename == 'app.js':
                filepath = 'app.js'
                content_type = 'application/javascript; charset=utf-8'
            else:
                # Retorna 404 padrão para buscas maliciosas / fuzzing (essencial para ffuf funcionar!)
                self.send_response(404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b"404 Not Found")
                return

            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Erro interno do servidor: {e}".encode('utf-8'))

    def do_POST(self):
        # API para ativar/desativar Firewall
        if self.path == '/api/toggle-firewall':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                global FIREWALL_ACTIVE
                FIREWALL_ACTIVE = bool(payload.get('active', False))
                
                # Registra alteração de firewall no IDS
                add_ids_log({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "src_ip": "IDS SYSTEM",
                    "src_port": 0,
                    "dst_ip": "FIREWALL",
                    "dst_port": 0,
                    "flags": "SYSTEM",
                    "seq": 0,
                    "ack": 0,
                    "description": f"ALTERAÇÃO DE ESTADO: Firewall alterado para {'ATIVO' if FIREWALL_ACTIVE else 'INATIVO'}"
                })
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "firewall_active": FIREWALL_ACTIVE}).encode('utf-8'))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # API de validação das Flags de cada Desafio
        if self.path == '/api/submit-flag':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode('utf-8'))
                challenge_id = int(payload.get('challenge_id', 0))
                flag_submitted = payload.get('flag', '').strip()
                
                success = False
                message = "Flag incorreta. Revise os comandos e tente novamente!"
                
                ans_dict = {
                    1: ["13b7994fae9387c2e1b598524ba1204ae404d02fa67016ed86c74183ab1aafca"],
                    2: ["64e925d1d7636b85b0646c8608522a178b6ac7c4bc836cc883626ac19a2c7bfa"],
                    3: ["1c8ed91fff97f1e59b392fcd98987b5faab1a344c3fca46b11ffc559d147c947"],
                    4: ["fcfe5f8210a246fa78e04f33d0f468a3678350988ff153fa9a255ddb171dc9e5"],
                    5: ["968c7f29e5c9a26769e33fe0134163341a9b9fb706a3f3c7d56325d9177c2fcc"],
                    6: ["f57e39a1af4d81c30ac5c9550cc388828f6635b7831b4febea91e361ffcbd2e2"],
                    7: ["e1d4157cb283f1ce10355ddff0bcf951f6c8efece03673488362b5c7f1d72330"],
                    8: ["268ee088d58a49b47c7806437c2c4b27d959416a3f0a86c9b210dac4187faafa"],
                    9: ["f177a80229db44f2162bfa1b5500cab2601b8bb1750706577a4aa67a113ef398", "11ee5e9af3eec0dc5afa6d11db4f11e5a7a9ec95a8668da51b20155729a32bbe"],
                    10: ["43484f0bec734558b890d7c46f5f1fe930a6477ac4aa21f8e02736f484e62561", "c9c2be9fdb0b42d17fb5b7a60ddc455109781682f15af87e2943c53a2a9973fa"],
                    11: ["40510175845988f13f6162ed8526f0b09f73384467fa855e1e79b44a56562a58"],
                    12: ["eb4df6f792c31f3b3d151343fbdaa08a5c626da9251197433200abbeadef50f3"],
                    13: ["d05973059efe8648b68101e62de5dc6c3335c6d473cae598b311208970f51894"],
                    14: ["12d2b5899af272f97b12c122d8ef375cf23fff84e351b65d5e2b12139fc7f872"],
                    15: ["2595465dd73b97d68d0d36583b2fb643ed96b7844e3a252e7bde6348b2853115"],
                    16: ["c7d50e82d5059c13c8e1ca2a9bb4305ed82580cce3476c629417688b917f502a"],
                    17: ["96f73d3c813b04a69d39105e6cc5a1acda062d1abb4232d530e560b65c095fe1", "f6deab2b121b0bb37c2e6b43bc9cd58c5422e9e638321f421515378e2856595b"],
                    18: ["34cc416e62a60414f0c84e1b1a1dbe39b74456bf4a16c8792cee14f8a3c22564", "dc88cb47691d3c455a0e3b0b6afd8c42855c8f4109fe6dc395a58f9dbc1dbef8"],
                    19: ["d8ef8078c0ab2fc0cd03387ffea5e976633f0f4e96be2f07829a64c4a8c2336e"],
                    20: ["89dbf71048801678ca4abfbaa3ea8f7c651aae193357a3e23d68e21512cd07f5"],
                    21: ["8c60e8f392430ef49ef386006d94c072127b84a972341d77640ae8b91d704177"],
                    22: ["5e6d0057ee5474a1bf8c44c4c0772e01a7af3ab740f997d0c5b73d7551e06680", "b629074b98f63057767c88e2d36691bb5c8b9ceafcc461971d215342baa0a90f"],
                    23: ["785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09"],
                    24: ["6f4b6612125fb3a0daecd2799dfd6c9c299424fd920f9b308110a2c1fbd8f443"],
                    25: ["b7a56873cd771f2c446d369b649430b65a756ba278ff97ec81bb6f55b2e73569"],
                    26: ["2858dcd1057d3eae7f7d5f782167e24b61153c01551450a628cee722509f6529"],
                    27: ["48449a14a4ff7d79bb7a1b6f3d488eba397c36ef25634c111b49baf362511afc"],
                    28: ["6d05621ab7cb7b4fb796ca2ffbe1a141e0d4319d3deb6a05322b9de85d69b923"],
                    29: ["757db91a80964d58a2b0d26bffd641bcbe142aae4f7f4771233619fa53fc179c"],
                    30: ["cb2dca9d3912259d6f5d8282a67fe80f783d182a25978bfc42d32fc6e660d130"],
                    31: ["55c82e43ca6ff80676a8fa02a24cc38321365409c03c60bdcfc99670c89edf3e", "55c82e43ca6ff80676a8fa02a24cc38321365409c03c60bdcfc99670c89edf3e", "7b60b8e351cbb80c47459ffe2c79f1a26404871f49294780fe47ad0e58c09350"],
                    32: ["1afaffe6834077cdd077550d4b2aaf913747c1d0557104e9f537ef4261c57bd0"],
                    33: ["189ea33e0d66a1d847f734f9164c9b38c10b4a062ad3350836630713a528ca63"],
                    34: ["8bff9e9b043560a5a548ed9bad9f4a7faeaf9258bea37e56ce8e1c09be2d3c0e"],
                    35: ["b4854f19b0a219bd5ef36f3a3c4856a0e7904a8b20830813412febd0fb088667"],
                    36: ["48db9125ac8b4c70f6eccdd2496afa6540b8f72c689a59c6c9fe2ceee405a5d1"],
                    37: ["a529ec66ff122ff06115703ef46a1074f9149d5dd43006c99c49cb537cc3b64e"],
                    38: ["fb43b944d9be17370da9ecbe277c786ab9e3358a2c4dca36a2fa09ef0659e58b"],
                    39: ["1b8e3b97e3a20e73b63ab5ea73d503836b1c3ca81e99d949e5ddd13dac94615a", "ea97b2d261c766aec1a7321846925b82a71b0486ae8235ff830fd4b64dc22da0"],
                    40: ["36790ecd55c2030dc553685bef719df653f413a20cdad1bfd1dc934c76686ddd"],
                    41: ["7ab4f62d323b0ca788f8742708674044b518eb6ca1a508ba4ef0e38adb8579e7"],
                    42: ["a2029ede7eea31815dda85486abfbccc2d13c0635ff67f2b3573cb6482be7008"],
                    43: ["a2f1a6d79bfb0fe6d2fe2f0f08c2f32ce53cc935520e9d8a9f8daa051b4f239b"],
                    44: ["24584b0bb279fdef771e92a94bbf640bb4f63efe173bb58740e7c87eaccff5b6", "7ef2fad58d1f2f12f5d78bdf7fc7ba3ad9529010ebd071c14d69394153f6106b"],
                    45: ["c3640546dbe71e12bd359084a5a3da42509a31cb3e929315cf67d3fbf479774d"],
                    46: ["3e891b6a1f2b4a3df2588af7744850888d28358fa38828c197fbaac63f700aa1"],
                    47: ["a6643c7e00152cab7c9f2859dcc55581201d180cdba80abf14586fa8eab1b88b", "97ac7c10d54d280035300b09dbb7b262c593d0b037fd619c6cc2da3c6a7b5f89", "2fdb58dfbe32f40bddff35e7f7739eec63b9c5cbf4985361efe0ebcb57a2d9b6"],
                    48: ["1a8fbc29ea81ad740160a5495aa00283fe12a34bd172e14f51a1e9c57184f911", "f0d30c9a10eb1483c7533dd96dfcad33c683a71c788ea34daa4d3d17547a6886"],
                    49: ["a2492191e48676f2c23e136f3310e9413454d498bd859efdbe0064379bf63752", "68a0f4e253b250d403239971939b791556927f619fe03c8125e368114cae2b25"],
                    50: ["24584b0bb279fdef771e92a94bbf640bb4f63efe173bb58740e7c87eaccff5b6", "e994a30c1761d004d4c486b5bff0fce10dfce2c9bc316c3786987c998b327eeb", "2bb80a7e96c3cbc847e7e546fb754727f3b5005af48b0bc3d2104331b52d71ed"],
                    51: ["685ca1b0e87cff465464f664d2a5f4b6207a01a3c0ec78125185b203bb45fbaf", "3d914f9348c9cc0ff8a79716700b9fcd4d2f3e711608004eb8f138bcba7f14d9"],
                    52: ["484930418be8b7b2a6812f61ab1e7ba16b069387f4909bcdac01951de7c533b7", "af386da04df4371d186ad1b0a36ec36e0edff957ddb267eda8f8a7707768f94d", "5ca2dd06f3e02daf27e42cefbe0a75405756507b83b07d0b52fbbac5ce46fce8"],
                    53: ["24584b0bb279fdef771e92a94bbf640bb4f63efe173bb58740e7c87eaccff5b6", "e994a30c1761d004d4c486b5bff0fce10dfce2c9bc316c3786987c998b327eeb", "2bb80a7e96c3cbc847e7e546fb754727f3b5005af48b0bc3d2104331b52d71ed"],
                    54: ["142c8344e34b1ce051fcc97ee853961729c7f549aa015b5e2ac4d359b32ee5be"],
                    55: ["a3a927d54158536750eab93674a8555c32c0decb9b800a05c1ce93d41704f6ce"],
                    56: ["bf84c4236ee1a74ab1a8707409f3bdcdd4324b819f3fda6924e607247c032010", "a241c3e477353243e58bc26dc15bec0aa485cfd9f14f3948d1f24afcfe0520e6"],
                    57: ["4b01fff428b8c2133662ad194ebf044825728f93d9350c2056c3671c8f92c4f2", "942ed01f0cbe6e42e34f942a8fc6f8d5b7b7743fb091ad2409fe9dac3879a4a8"],
                    58: ["dc4030f9688d6e67dfc4c5f8f7afcbdbf5c30de866d8a3c6e1dd038768ab91c3"],
                    59: ["40dc4827cc7ec8595947a707efda975ab59c1d09243d2db7eb313fbf7746883c", "e6d9706a2a8d4bfa49a89b9b6ecdc024e7c97be09dcbe4b387b80392e8a2fc7d"],
                    60: ["278ccace7eac2efec20503e06c47e1b30cadf21b256fc8c725809b20b4c959c3"],
                    61: ["e095dd2bed5862a07b8cff374363b8dbb82f4810c140395b296653f70e27bd2b"],
                    62: ["9114f82dbf33143a96e7a73dbd54e94c1ea9a2a67cfd854fe1789c33a8fdc374"],
                    63: ["01e56d5e359baca7e975e9502393d4569c5f7e29e1f5aed117044eabe546d34d"],
                    64: ["ecd4d56cbc1d62c2000b920d35b95d84f6dfea726b604d68b82f8fa14d218ff8"],
                    65: ["c928b9579157cf42711c12b51ba881229e1b89dd7fc1a1868c435185e2ed2196"],
                    66: ["103edfbd31840b9185fb9e9206bb8a59ed42e5002916b9d1ec9184d0b567b436"],
                    67: ["eab6b8b065131cab9718da4fc7c26d8f7c9e7c1e327a603e6f37aef921750a3d"],
                    68: ["ecd4d56cbc1d62c2000b920d35b95d84f6dfea726b604d68b82f8fa14d218ff8"],
                    69: ["df082a4fa58469aceb181729231c5759f19e3a0b1f0ccb0ffd82e8b8de85155d", "4aa9b13943b23f95d1013a868d43da91ff64cfc477223c09f143c312ef6cda2b", "df082a4fa58469aceb181729231c5759f19e3a0b1f0ccb0ffd82e8b8de85155d", "acae31aab4ec087ab72f5bd597e2d69ea054f9e04f3e9e2585bcb16dee8d1bd1"],
                    70: ["dc8a130d818f01c7824091e2fd68ae9b9d24b45c87ee369c3c2d384b4dbf2a8a", "67f1caab433b6b379f008676e97ebf19a0e55a0f5c10ea4253546a69f76858f8"],
                    71: ["54f200c686596bf5c4dcd7dc0e4e0142a3504d8bcfcc54dc26997d5b74a7ed07"],
                    72: ["acbc0d6e487c6237057049522103a742d1333bee92bfbbedf205e08be934d64b"],
                    73: ["5ccd397b7b1bed722d57ba5884ab7469b601cf6f0985a8153b95ae26289d4644", "cdded7231a0c512ed51b072e9982f725870905b7d5c8c6df5e258910a6d77f07"],
                    74: ["cdded7231a0c512ed51b072e9982f725870905b7d5c8c6df5e258910a6d77f07"],
                    75: ["b8a1e02bf473e8802a6457797503df8317d57833b95c3e823c6e04f4f365ef00", "b8a1e02bf473e8802a6457797503df8317d57833b95c3e823c6e04f4f365ef00", "b47074ab486c2d2a1c35f6c30ebf46e33348c2cec199991059a8826b2d95e582"],
                    76: ["4e5df7a6cd0f0488e12e007d4fedafb5f3379d3dd805bd07ea58eec33da47eca"],
                    77: ["a13d77be06550e10088e545cd6ccd6daf4fff00ec084b0ca2c72a895b4d51483"],
                    78: ["89c277dc28df0b0ed89d79265ee93c09538f70f66c8850e39812d9a0472f319a"],
                    79: ["f3062ed5516c255277cce2b45b35a7e632ce7bbdb705ccf8206f9c6ac8545eec"],
                    80: ["ec947170824a09f8b502f402ac3ef7eb02b6a4096b54a190836b79d5155e0ed2"],
                    81: ["3e2d8a9468c7a7b5280542d32194f32f72c7e670e6c145364f82d6aafc8200ab"],
                    82: ["899ece5fb43f7e0ddbbcfec0828707b830ff98242c1be9cd987541d810aefda0"],
                    83: ["d4ecd6ef93448e5ae2083cf8a445282b46b597ccde57e89c0c785fc7cdaa69ef"],
                    84: ["5671c9b05916ba4c093a158dd36b2d9f703ad98b4a2ebef4a0864014d3839060"],
                    85: ["1f07979439c5d1ca1e5ed141cadc8d58892bc54b474e851a026a73b7659ba248"],
                    86: ["46f80c185776d413a9fdb119d4f943cc7fbd1981a636174df433bee9933bd9aa"],
                    87: ["c3a3df4282e568cee9c2c2e49aa141da3de69631a31a201b99838faf1a7f0d29"],
                    88: ["de75ad58228bf5f0ffb99b04dced17644f4cfda7acb7b64e3ade4f52ca496e73"],
                    89: ["280582fd985edf3d1256ad529455867ceee53f71f006d47541c57c4d63ebbf3b"],
                    90: ["90827c5d6293a29e04c2a043f75a145be132a25b6d1edb7738130823b144ab1b"],
                    91: ["27badc983df1780b60c2b3fa9d3a19a00e46aac798451f0febdca52920faaddf"],
                    92: ["c3ea99f86b2f8a74ef4145bb245155ff5f91cd856f287523481c15a1959d5fd1"],
                    93: ["d26eae87829adde551bf4b852f9da6b8c3c2db9b65b8b68870632a2db5f53e00"],
                    94: ["6b3c238ebcf1f3c07cf0e556faa82c6b8fe96840ff4b6b7e9962a2d855843a0b"],
                    95: ["0604cd3138feed202ef293e062da2f4720f77a05d25ee036a7a01c9cfcdd1f0a"],
                    96: ["4b3768d65f14f5ffdfdfa7af959dd49c950d53e84062d45b441f85c2d25da859", "77727dc67179271266a04e004bf06a6c830ce5e7e92b950a1d8dc9e152c62271"],
                    97: ["5d2d6c34ffb7f7ea236548bb923a88c86b1a1d189f353658b745a29ff1866455"],
                    98: ["ebdb09b474753ed87e404a24a2f3db172ca1a3512fff2f2627c3fb5653b7ab42", "078786d835ebaf03c8f09ac8d98a492332697c2ee496c38b48ea3bb93cba665c", "078786d835ebaf03c8f09ac8d98a492332697c2ee496c38b48ea3bb93cba665c"],
                    99: ["f0339bd9d4c2811b7eb751b301753d9325d4b9b53e91bddbbc92a277a854cb85"],
                    100: ["9aee6b1bcdf617d8e39bb1f2b624c68ea33deb9d48e0364aeaded836d3d00293"],
                    101: ["73ab66a033c267e00b7429bb256f6deb2734ebc4cd4ff5b564a8c9f9b2c8a719"],
                    102: ["9e15eb5af2b09c82436049b41108347dd1361571f53dd22d20fc33c0dc18c01f"],
                    103: ["eb84c0688c3a9382649d65efda16cbf68d073d3aef8c589c7fcb9641f9e59fba"],
                    104: ["53bc8d1b5881db85ac3788bd16719ece45ac0c562dab83f28bd7ee8086fbadf8"],
                    105: ["1da81416b68b3c688347a0f851af7427ba2d845d2580dea76b12a3e6cbca9d16"],
                    106: ["5b8b09cf56181f798ff6692bfc7017680012022c7eec8e642dac9afcd822e850"],
                    107: ["36790ecd55c2030dc553685bef719df653f413a20cdad1bfd1dc934c76686ddd"],
                    108: ["2b950e631acf9442e54444a005e4d90f851cf06cdcaea2ed1108eb4b02fe2b5d"],
                    109: ["380661aef1006ec9edeab638a627e0f86b93479015478ec06794d5a5abe6b109"],
                    110: ["9a95ea400e2a0e457f8c5a8a65c734c36ab9cdf6e66f5ba866711e3bfc1bef1b"],
                    111: ["032445d961bcc5cef05bc05818f1d1dee0bead3a1e51928c5131ea4ec9c313c3"],
                    112: ["4792e5103848cf414d2ca0aad66565e17ec0b4b1759906fecd42627d38fcac45"],
                    113: ["95784973cc639977bff93619700168505cb8f7855e44fa643d34622a43706c87"],
                    114: ["e764cf98aeabea1b53f1459072d16149625677d2867cf7e54b6547d16a8c317d"],
                    115: ["dd24eae77df079607b5ea1341f7fdefc06b771bee5c676d48b2618e05f261fb3"],
                    116: ["80f26b77dce3b0c3da9b78977270e7d245a45825d66d61b1905f3646ced7d98a"],
                    117: ["18feab5a04c46a39eafd2f187b83d0e1b65d78fd04e5d5917415730dfe79484f"],
                    118: ["986b5426ef3e18f20e61cf71449d4107bf2cb54eafb5d54bc43c2ad49de9bf7f"],
                    119: ["7174235fb6fb820a9de1a6e4eb9451c9dc54c9423f042518f58b63ace9d38cd8"],
                    120: ["6f0e59f15c7b0241580b7dd3dc03113d97186361d900d477fd5d6b3d986df2e9"],
                    121: ["ce14f3815bb7e344fdd07388bc88982639a1ee90d1a5060360773865f91a48da"],
                    122: ["1547aec67fb1df8c90264ad2fbb261fe1dc4c4f185416fc80edf71afeaa13b71"],
                    123: ["d038d7f03b0de44d96dd68c488610cb782010fcf21a80d3f816eef5992cc8654"],
                    124: ["e5129e3a23a3526d38fbda143d66a95d8ef967686893f9f14b76376aee6dc8cd"],
                    125: ["dfe4950f6992bd7b256fe5ab695d73fc62316661730b8cb834b13a6a00f9cd33"],
                    126: ["e095dd2bed5862a07b8cff374363b8dbb82f4810c140395b296653f70e27bd2b"],
                    127: ["54f200c686596bf5c4dcd7dc0e4e0142a3504d8bcfcc54dc26997d5b74a7ed07"],
                    128: ["acbc0d6e487c6237057049522103a742d1333bee92bfbbedf205e08be934d64b"],
                    129: ["01e56d5e359baca7e975e9502393d4569c5f7e29e1f5aed117044eabe546d34d"],
                    130: ["3cbd6588406ed8f8b6bfa8f2a5815ce64fcb8c03cc2e81457fa09c4f75aa2f05"],
                    131: ["5efa6e23d6586d98d3362f9163e185e81bd9de13fbdf60efd0eeff61f005e44d"],
                    132: ["5fa14dfdfa7bf7ddeeac7d12d5fc4bbba9f9c2aff655aa71842a9910a5c0e7b0"],
                    133: ["a7617388ce5dfb70049c646702c63b173a57b3e24074716f17507d7aa6c591e5"],
                    134: ["cd6e6db75b3d01fb384300dafcae9d906775fbb722866a478eee97a93a17e810"],
                    135: ["75da08a6ab62fb8455f8f0afaeffcac7b2b9f4b35fff8859f2ed7574bb235e80"],
                    136: ["62a3653a3ae54b3d186cc06176b3b0703f34bec618c94c04afdfc022d8c7a35a"],
                    137: ["893123cc36799872c0a35da322977486d263be8072644743eb55c40c1a3d7b71"],
                    138: ["4c535351bfb6bb67aec3868e7d2dc7f4135f36bfaeb032b8b45ce75e7584af3e"],
                    139: ["7de2c333281ea5cb7eb14de8dfda5455b0fdb3656cce03cb53d3566ba7fe0bbc"],
                    140: ["9d11f1f2108fe6a538e5b3376a21ae0f63ef55aa1b58fdf5ac552fb9255f0779"],
                    141: ["569b4e7cc6effaf913c7ffb57424fb691b3ea345a1be6e3ed29caaf94541fe52"],
                    142: ["6d67729b9d746dd8a814256ccd2a1d3cb5703115e63077a71ff8d40ed2a5e203"],
                    143: ["bd4e70889f1bdf08ccccbf4901f026f5bb2781ba3cc6d292f58c9e1d73930014"],
                    144: ["b300bdeb0ec7c566babff9ce8321980ba6de648138afc2f2289d605d8ec530f8"],
                    145: ["f67210d6cc20dcc85f6c016d5eab7e3b30c9aabdfa4e9c8e55f998697b05d8ea"],
                    146: ["c57601e508a99988edcdb253a2435f69d639cbfd06ff26e1c445e0409dd16238"],
                    147: ["f3b1cfcf869b72b4d60a7d3546b4550dcc8d5501f92e61806c38e559ef13cd8a"],
                    148: ["efd538464c176e84d330cf436979a30c6ef54802a70a365deeafcce9f7524b75"],
                    149: ["eddffdd04fff5a33ba63bab83b0f996c54efaf9b375f8ffdc2afeaf420c51bd0"],
                    150: ["1be02f96204640028840e5d8c6bf3b6b7b0869f7ece535974f22a6d2af76efc6"]
                }

                if challenge_id in ans_dict:
                    def clean_str(s):
                        import unicodedata
                        s_norm = unicodedata.normalize('NFKD', s)
                        return "".join([c for c in s_norm if not unicodedata.combining(c)]).upper().strip()

                    import hashlib
                    clean_submit = clean_str(flag_submitted)
                    submit_hash = hashlib.sha256(clean_submit.encode('utf-8')).hexdigest()

                    if submit_hash in ans_dict[challenge_id]:
                        success = True
                        message = f"Excelente! Resposta correta para o Desafio {challenge_id}!"
                    else:
                        success = False
                        message = "Flag ou resposta incorreta. Tente novamente!"

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": success, "message": message}).encode('utf-8'))
                
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

def start_web_server():
    """Inicia o servidor HTTP multithread"""
    global PORT_WEB
    try:
        server = ThreadedHTTPServer(('0.0.0.0', PORT_WEB), LabHTTPHandler)
        print(f"[+] Painel de Laboratório ativo em http://127.0.0.1:{PORT_WEB}")
        server.serve_forever()
    except OSError as e:
        if e.errno == 98 and PORT_WEB == 80:
            print(f"[!] Erro: A porta 80 já está em uso (provavelmente pelo Apache/nginx).")
            print(f"[*] Para liberar a porta 80, você pode parar o Apache com: sudo systemctl stop apache2")
            print(f"[*] Tentando subir o laboratório na porta alternativa 8080...")
            PORT_WEB = 8080
            try:
                server = ThreadedHTTPServer(('0.0.0.0', PORT_WEB), LabHTTPHandler)
                print(f"[+] Painel de Laboratório ativo em http://127.0.0.1:{PORT_WEB}")
                server.serve_forever()
            except Exception as ex:
                print(f"[!] Erro ao iniciar Servidor Web na porta alternativa {PORT_WEB}: {ex}")
                sys.exit(1)
        else:
            print(f"[!] Erro ao iniciar Servidor Web na porta {PORT_WEB}: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Erro inesperado ao iniciar Servidor Web: {e}")
        sys.exit(1)


# --- FLUXO PRINCIPAL ---
if __name__ == "__main__":
    print("="*60)
    print("   LABORATÓRIO DE VARREDURA, ANÁLISE DE TRÁFEGO E ENUMERAÇÃO   ")
    print("="*60)
    
    if not RUNNING_AS_ROOT:
        print("[!] AVISO: Executando sem permissão de superusuário (sudo).")
        print("[!] O IDS (Raw Sniffer) estará desativado e o site subirá na porta 8080.")
        print("[!] Para a experiência completa de laboratório local, execute:")
        print("    sudo python3 server.py")
        print("-" * 60)

    # Thread 1: Sniffer Raw Socket
    t_sniffer = threading.Thread(target=start_raw_sniffer, daemon=True)
    t_sniffer.start()

    # Thread 2: Serviço Simulado na porta 9001
    t_ftp = threading.Thread(target=start_mock_ftp, daemon=True)
    t_ftp.start()

    # Iniciar outros servidores mock de portas
    for target_fn, name in [
        (start_mock_9002, "Port 9002 (Netcat interactive)"),
        (start_mock_smtp, "SMTP (9003)"),
        (start_mock_telnet, "Telnet (9004)"),
        (start_mock_mysql, "MySQL (9006)"),
        (start_mock_redis, "Redis (9008)"),
        (start_mock_udp, "UDP (9009)"),
        (start_mock_pop3, "POP3 (9110)"),
        (start_mock_imap, "IMAP (9143)"),
        (start_mock_high, "High TCP (9555)")
    ]:
        t = threading.Thread(target=target_fn, daemon=True)
        t.start()

    # Thread 3: Servidor Web (Dashboard e APIs)
    # Rodamos na thread principal
    start_web_server()
