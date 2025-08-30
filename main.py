#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brain File
Commands:
 /s <keyword> [ext:<ext>] [type:<filetype>] : 検索（filename + sha1 + relay_nodes）
 /g <sha1>                                  : 自動リレー経由で匿名ダウンロード
 /cache                                     : ピアキャッシュ表示
 /help /exit
"""
import os, sys, json, socket, threading, asyncio, hashlib, secrets, re, random, mimetypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

if os.name == 'nt':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# --- config.json 読み込み ---
CONFIG_FILE = 'config.json'

# デフォルト値
DEFAULT_PORT = 8468
FILES_DIR = 'shared_files'
DOWNLOAD_DIR = 'downloads'
CACHE_FILE = 'peer_cache.json'
LISTEN_ADDR = ''

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE,'r',encoding='utf-8') as f:
            config=json.load(f)
            PORT=config.get("port",DEFAULT_PORT)
            FILES_DIR=config.get("files_dir",FILES_DIR)
            DOWNLOAD_DIR=config.get("download_dir",DOWNLOAD_DIR)
            CACHE_FILE=config.get("cache_file",CACHE_FILE)
    except Exception as e:
        print(f"Config load failed: {e}")
        PORT = DEFAULT_PORT
else:
    PORT = DEFAULT_PORT

os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def promote_profile():
    profile_url = "https://x.com/xx_lucivolic"
    print(f"🚀 Check out my latest updates and insights on X: {profile_url}")
    print("🔔 Don't forget to follow me for more content!")

print("⚠️ 重要: VPN 未接続での起動は危険です。必ず VPN 経由で使用してください。")

NODE_ID = secrets.token_hex(16)
print(f"node_id: {NODE_ID}")

# AES-CTR
def encrypt_message(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    return cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()

def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    return cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

# DH helpers
p = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF', 16)
g = 2

def generate_dh_keypair():
    priv = secrets.randbits(256)
    pub = pow(g, priv, p)
    return priv, pub

def compute_shared_key(peer_pub: int, priv: int) -> bytes:
    shared = pow(peer_pub, priv, p)
    return hashlib.sha256(str(shared).encode()).digest()

# --- peer cache ---
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE,'r',encoding='utf-8') as f:
                return json.load(f)
        except: return []
    return []

def save_cache(cache):
    try:
        with open(CACHE_FILE,'w',encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except: pass

def add_to_cache(ip, port, node_id=None):
    cache = load_cache()
    entry = {"ip": ip,"port":port,"node_id":node_id}
    if entry not in cache:
        cache.append(entry)
        save_cache(cache)

def merge_cache(remote_cache):
    cache = load_cache()
    changed = False
    for e in remote_cache:
        ip = e.get("ip")
        port = e.get("port",PORT)
        nid = e.get("node_id")
        entry = {"ip": ip,"port":port,"node_id":nid}
        if entry not in cache:
            cache.append(entry)
            changed = True
    if changed:
        save_cache(cache)

# --- utils ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8",80))
        ip = s.getsockname()[0]
    except:
        ip="127.0.0.1"
    finally: s.close()
    return ip

LOCAL_IP = get_local_ip()
print(f"Local IP detected: {LOCAL_IP}")

def safe_path_join(base, filename):
    base = os.path.abspath(base)
    candidate = os.path.abspath(os.path.join(base, filename))
    if not (candidate==base or candidate.startswith(base+os.sep)):
        return None
    return candidate

def extract_keywords(filename):
    name=os.path.splitext(filename)[0]
    words=re.split(r'[^a-zA-Z0-9]+',name)
    words.append(name)
    words.append(filename)
    return set(w.lower() for w in words if w)

# --- 空きポート自動選択 ---
def select_available_port(start_port):
    port = start_port
    while True:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            try:
                s.bind(('',port))
                return port
            except OSError:
                port += 1

PORT = select_available_port(PORT)
print(f"Using port: {PORT}")

# --- low-level secure handler ---
MAX_RECV=65536
def handle_client_secure(conn, addr):
    try:
        server_priv, server_pub = generate_dh_keypair()
        conn.sendall(str(server_pub).encode()+b'\n')
        raw=b''
        while b'\n' not in raw:
            part = conn.recv(4096)
            if not part: return
            raw += part
        client_pub_line, rest = raw.split(b'\n',1)
        try: client_pub=int(client_pub_line.decode().strip())
        except: return
        session_key = compute_shared_key(client_pub, server_priv)
        nonce = secrets.token_bytes(16)
        conn.sendall(nonce)
        enc_req = rest or conn.recv(MAX_RECV)
        try:
            req = json.loads(decrypt_message(session_key, enc_req, nonce).decode(errors='ignore'))
        except: return
        rtype = req.get("type")
        payload = req.get("payload",{})
        if rtype=="CACHE_EXCHANGE":
            merge_cache(payload.get("cache",[]))
            add_to_cache(LOCAL_IP,PORT,NODE_ID)
            resp={"status":"OK","cache":load_cache()}
            conn.sendall(encrypt_message(session_key,json.dumps(resp).encode(),nonce))
            return
        if rtype=="SEARCH":
            kw=payload.get("keyword","").lower()
            results=[]
            for fname in os.listdir(FILES_DIR):
                kws=extract_keywords(fname)
                if kw in kws or kw in fname.lower():
                    sha1=hashlib.sha1(fname.encode()).hexdigest()
                    results.append({"filename":fname,"sha1":sha1,"relay_nodes":[NODE_ID]})
            resp={"status":"OK","results":results}
            conn.sendall(encrypt_message(session_key,json.dumps(resp).encode(),nonce))
            return
        if rtype=="GET":
            filename=payload.get("filename","")
            fp=safe_path_join(FILES_DIR,filename)
            if not fp or not os.path.exists(fp):
                conn.sendall(encrypt_message(session_key,b'NOTFOUND',nonce))
                return
            with open(fp,'rb') as f:
                while True:
                    chunk=f.read(4096)
                    if not chunk: break
                    conn.sendall(encrypt_message(session_key,chunk,nonce))
            return
        if rtype=="RELAY_GET":
            target_nid=payload.get("target_node_id")
            filename=payload.get("filename","")
            holder=None
            for p in load_cache():
                if p.get("node_id")==target_nid: holder=p; break
            if holder is None:
                resp={"status":"ERR","msg":"holder_not_found"}
                conn.sendall(encrypt_message(session_key,json.dumps(resp).encode(),nonce))
                return
            try:
                holder_data = send_encrypted_request(holder['ip'],holder.get('port',PORT),
                                {"type":"GET","payload":{"filename":filename}},stream=True)
                if holder_data==b'NOTFOUND' or holder_data is None:
                    conn.sendall(encrypt_message(session_key,b'NOTFOUND',nonce))
                    return
                idx=0
                while idx<len(holder_data):
                    chunk=holder_data[idx:idx+4096]
                    conn.sendall(encrypt_message(session_key,chunk,nonce))
                    idx+=len(chunk)
            except: conn.sendall(encrypt_message(session_key,b'NOTFOUND',nonce))
            return
        resp={"status":"ERR","msg":"unknown"}
        conn.sendall(encrypt_message(session_key,json.dumps(resp).encode(),nonce))
    finally:
        try: conn.close()
        except: pass

def file_server():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((LISTEN_ADDR,PORT))
    s.listen(128)
    print(f"File server listening on port {PORT} (anonymous relay enabled)")
    while True:
        conn,addr=s.accept()
        threading.Thread(target=handle_client_secure,args=(conn,addr),daemon=True).start()

# --- client ---
def send_encrypted_request(ip,port,request,timeout=8,stream=False):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip,port))
        raw=b''
        while b'\n' not in raw:
            part=sock.recv(4096)
            if not part: raise ConnectionError("no server pub")
            raw+=part
        server_pub_line,rest=raw.split(b'\n',1)
        server_pub=int(server_pub_line.decode().strip())
        client_priv, client_pub=generate_dh_keypair()
        sock.sendall(str(client_pub).encode()+b'\n')
        session_key=compute_shared_key(server_pub,client_priv)
        nonce=sock.recv(16)
        enc_req=encrypt_message(session_key,json.dumps(request).encode(),nonce)
        sock.sendall(enc_req)
        if request.get("type")=="GET" or stream:
            chunks=[]
            while True:
                try: enc=sock.recv(4096)
                except: break
                if not enc: break
                dec=decrypt_message(session_key,enc,nonce)
                if dec==b'NOTFOUND': return b'NOTFOUND'
                chunks.append(dec)
            return b''.join(chunks)
        else:
            enc=sock.recv(65536)
            if not enc: return None
            dec=decrypt_message(session_key,enc,nonce)
            try: return json.loads(dec.decode())
            except: return dec
    finally:
        try:sock.close()
        except: pass

def exchange_cache_with_peer(ip,port):
    try:
        req={"type":"CACHE_EXCHANGE","payload":{"cache":load_cache()+[{"ip":LOCAL_IP,"port":PORT,"node_id":NODE_ID}]}}
        send_encrypted_request(ip,port,req)
    except: pass

def search_keyword_across_cache(keyword, filters=None):
    if filters is None: filters={}
    results=[]
    for fname in os.listdir(FILES_DIR):
        if keyword.lower() in fname.lower() and match_file_filters(fname, filters):
            sha1=hashlib.sha1(fname.encode()).hexdigest()
            results.append({"filename":fname,"sha1":sha1,"relay_nodes":[NODE_ID]})
    cache=load_cache()
    with ThreadPoolExecutor(max_workers=8) as exe:
        futures={exe.submit(send_encrypted_request,p.get("ip"),p.get("port",PORT),
                            {"type":"SEARCH","payload":{"keyword":keyword}}):p for p in cache}
        for fut in as_completed(futures):
            try:
                data=fut.result()
                if not data: continue
                for r in data.get("results",[]):
                    if match_file_filters(r["filename"],filters):
                        results.append(r)
            except: continue
    unique={r["sha1"]:r for r in results}
    return list(unique.values())

def match_file_filters(filename, filters):
    ext = filters.get("ext")
    if ext and not filename.lower().endswith(f".{ext.lower()}"):
        return False
    ftype = filters.get("type")
    if ftype:
        mime, _ = mimetypes.guess_type(filename)
        if mime is None: return False
        if ftype.lower()=="image" and not mime.startswith("image/"): return False
        if ftype.lower()=="video" and not mime.startswith("video/"): return False
        if ftype.lower()=="audio" and not mime.startswith("audio/"): return False
        if ftype.lower()=="document" and not mime.startswith(("text/","application/pdf","application/msword")): return False
    return True

def parse_search_command(cmd: str):
    parts = cmd.split()
    keyword = ""
    filters = {}
    for p in parts[1:]:
        if p.startswith("ext:"): filters["ext"]=p[4:]
        elif p.startswith("type:"): filters["type"]=p[5:]
        else: keyword += p + " "
    return keyword.strip(), filters

def select_relay(relay_nodes):
    if not relay_nodes: return None
    cache=load_cache()
    candidates=[p for p in cache if p.get("node_id") in relay_nodes]
    if not candidates: return None
    return random.choice(candidates)

def download_via_relay(filename, relay_nodes):
    relay=select_relay(relay_nodes)
    if relay is None:
        print("No relay available; cannot perform anonymous download.")
        return False
    data=send_encrypted_request(relay["ip"],relay.get("port",PORT),
                                {"type":"RELAY_GET","payload":{"target_node_id":NODE_ID,"filename":filename}},stream=True)
    if data==b'NOTFOUND' or data is None:
        print("File not found via relay.")
        return False
    fp=os.path.join(DOWNLOAD_DIR,f"{hashlib.sha1(filename.encode()).hexdigest()}_{filename}")
    with open(fp,'wb') as f: f.write(data)
    print(f"{filename} downloaded to {fp}")
    return True

# --- console ---
async def console_loop():
    print("Commands:\n /s <keyword> [ext:<ext>] [type:<filetype>] : search\n /g <sha1> : download via relay\n /cache : show peer cache\n /help /exit")
    loop=asyncio.get_running_loop()
    while True:
        try: cmd=await loop.run_in_executor(None, lambda: input("> ").strip())
        except EOFError: break
        if not cmd: continue
        if cmd=="/exit": break
        elif cmd.startswith("/s "):
            keyword, filters = parse_search_command(cmd)
            res = await loop.run_in_executor(None, search_keyword_across_cache, keyword, filters)
            if res:
                print("Found:")
                for r in res:
                    print(f" - {r.get('filename')} SHA1={r.get('sha1')} relay_nodes={r.get('relay_nodes')}")
            else: print("No results.")
        elif cmd.startswith("/g "):
            parts=cmd.split()
            if len(parts)!=2: print("Usage: /g <sha1>"); continue
            sha1=parts[1]
            results=search_keyword_across_cache("")
            target=None
            for r in results:
                if r.get("sha1")==sha1: target=r; break
            if not target: print("File not found in network."); continue
            download_via_relay(target["filename"],target["relay_nodes"])
        elif cmd=="/cache":
            for p in load_cache(): print(f" - {p.get('ip')}:{p.get('port')} {p.get('node_id')}")
        elif cmd=="/help":
            print("Commands:\n /s <keyword> [ext:<ext>] [type:<filetype>] : search\n /g <sha1> : download via relay\n /cache : show peer cache\n /help /exit")
        else: print("Unknown command.")

# --- bootstrap & local register ---
def bootstrap_peers():
    for peer in load_cache(): exchange_cache_with_peer(peer.get('ip'),peer.get('port',PORT))
    add_to_cache(LOCAL_IP,PORT,NODE_ID)

def local_register_files():
    for fn in os.listdir(FILES_DIR):
        sha1=hashlib.sha1(fn.encode()).hexdigest()
        print(f"Local file available: {fn} SHA1={sha1}")

async def main():
    threading.Thread(target=file_server,daemon=True).start()
    bootstrap_peers()
    local_register_files()
    await console_loop()

if __name__=="__main__":
    promote_profile()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
