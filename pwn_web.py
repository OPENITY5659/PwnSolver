#!/usr/bin/env python3
"""
PwnSolver Web API — 在WSL内常驻运行，通过HTTP交互
让AI/用户在对话中直接操作pwn工具并获得完整反馈

启动: python3 pwn_web.py [port]
默认端口: 8787

API:
  GET  /status                — 健康检查
  POST /solve                 — 提交解题任务 {binary, libc?, timeout?} → {task_id}
  GET  /solve/<task_id>       — 获取任务结果 {status, stdout, stderr, rc}
  POST /interact              — 交互式调试 {binary, cmd, data?}
                                  cmd: start | send | sendline | recv | recvall
                                       | status | close | info | maps | pid
  GET  /interact/<sid>        — 获取交互会话输出
"""
import json, os, sys, threading, subprocess, time, traceback, uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

WORKSPACE = Path(__file__).parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
HOST = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'  # 默认仅本机, 防局域网未授权RCE
MAX_BODY = 1 << 20       # body上限1MB
MAX_TASKS = 32           # 并发任务上限
MAX_SESSIONS = 16        # 交互会话上限
MAX_TIMEOUT = 300        # solver timeout上限(秒)
MAX_OUTPUT = 1 << 20     # 会话输出累积上限1MB
HANDLER_TIMEOUT = 10     # HTTP请求读超时(秒)
TOKEN = os.environ.get('PWNWEB_TOKEN') or ''  # 非空时要求X-Token头认证
SESSION_TTL = 600        # 会话空闲回收时间(秒)

# 非回环地址必须启用token认证, 防条件性未授权RCE
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1')
if HOST not in LOOPBACK_HOSTS and not TOKEN:
    print(f"[pwn-web] 错误: 绑定非回环地址{HOST}必须设置PWNWEB_TOKEN", flush=True)
    sys.exit(1)

# ============ 任务管理 ============
class TaskManager:
    def __init__(self):
        self.tasks = {}      # task_id -> {status, stdout, stderr, rc, start}
        self.lock = threading.Lock()
    
    def submit(self, binary, libc=None, timeout=60):
        task_id = uuid.uuid4().hex[:12]
        with self.lock:
            if len(self.tasks) >= MAX_TASKS:
                return None, 'task limit reached'
            self.tasks[task_id] = {'status': 'running', 'stdout': '', 'stderr': '', 'rc': None, 'start': time.time()}
        
        def worker():
            cmd = ['python3', '-W', 'ignore', str(WORKSPACE / 'pwn_solver' / 'solver.py'),
                   str(binary)]
            if libc:
                cmd += ['-l', str(libc)]
            cmd += ['-t', str(timeout)]
            
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding='utf-8', errors='replace')
                try:
                    out, err = proc.communicate(timeout=timeout + 60)
                    rc = proc.returncode
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = proc.communicate()
                    rc = -1
                    err += "\n[Timeout] solver killed"
                # 输出截断防内存耗尽
                out, err = out[-MAX_OUTPUT:], err[-MAX_OUTPUT:]
            except Exception as e:
                # 详情仅日志, 不泄露内部路径到任务结果
                print(f'[pwn-web] solver start error: {type(e).__name__}: {e}', flush=True)
                out, err, rc = '', 'solver start failed', -2
            
            with self.lock:
                self.tasks[task_id] = {'status': 'done', 'stdout': out, 'stderr': err, 'rc': rc,
                                       'start': self.tasks[task_id]['start']}
                # 回收最旧已完成任务, 防槽位永久占满
                done_ids = [tid for tid, t in self.tasks.items() if t['status'] == 'done']
                for tid in sorted(done_ids, key=lambda t: self.tasks[t]['start'])[:-MAX_TASKS]:
                    del self.tasks[tid]
        
        threading.Thread(target=worker, daemon=True).start()
        return task_id
    
    def get(self, task_id):
        with self.lock:
            return self.tasks.get(task_id)

# ============ 交互会话 ============
class InteractManager:
    """交互式调试会话 — 直接操作binary进程"""
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
    
    def start(self, binary):
        sid = uuid.uuid4().hex[:8]
        with self.lock:
            if len(self.sessions) >= MAX_SESSIONS:
                return None, 'session limit reached'
        try:
            # 用pwntools启动
            from pwn import process, context
            context.log_level = 'error'
            bin_str = binary.decode('utf-8', 'replace') if isinstance(binary, bytes) else binary
            p = process(bin_str.encode())
            with self.lock:
                self.sessions[sid] = {
                    'proc': p, 'binary': bin_str,
                    'output': b'', 'closed': False,
                    'last_active': time.time()
                }
            return sid, None
        except Exception as e:
            # 异常详情仅日志, 不泄露内部路径
            print(f'[pwn-web] start error: {type(e).__name__}: {e}', flush=True)
            return None, 'start failed'
    
    def cmd(self, sid, cmd, data=None):
        with self.lock:
            sess = self.sessions.get(sid)
            if not sess:
                return {'error': f'session {sid} not found'}
            p = sess['proc']
            sess['last_active'] = time.time()
        
        # 惰性回收: 进程已退出且空闲超30s的会话
        with self.lock:
            dead = [s for s, v in self.sessions.items()
                    if v['proc'].poll() is not None and time.time() - v.get('last_active', 0) > 30]
            for s in dead:
                try:
                    self.sessions[s]['proc'].close()
                except:
                    pass
                self.sessions.pop(s, None)
        
        try:
            if cmd == 'send':
                if isinstance(data, str):
                    data = data.encode('latin-1', 'replace')
                elif data is None:
                    data = b''
                p.send(data)
                return {'ok': True, 'sent': len(data)}
            elif cmd == 'sendline':
                if isinstance(data, str):
                    data = data.encode('latin-1', 'replace')
                elif data is None:
                    data = b''
                p.sendline(data)
                return {'ok': True, 'sent': len(data)}
            elif cmd == 'recv':
                try:
                    out = p.recv(timeout=3)
                    sess['output'] = (sess['output'] + out)[-MAX_OUTPUT:]
                    return {'ok': True, 'data': out.decode('latin-1', 'replace'), 'hex': out.hex()}
                except Exception as e:
                    # 详情仅日志, 不泄露内部路径
                    print(f'[pwn-web] recv error: {type(e).__name__}: {e}', flush=True)
                    return {'ok': False, 'error': 'recv failed', 'data': '', 'hex': ''}
            elif cmd == 'recvall':
                out = p.recvall(timeout=3)
                sess['output'] = (sess['output'] + out)[-MAX_OUTPUT:]
                return {'ok': True, 'data': out.decode('latin-1', 'replace'), 'hex': out.hex()}
            elif cmd == 'status':
                return {'ok': True, 'poll': p.poll()}
            elif cmd == 'close':
                try:
                    p.close()
                except:
                    pass
                with self.lock:
                    sess['closed'] = True
                    # 回收会话条目, 防槽位占满
                    self.sessions.pop(sid, None)
                return {'ok': True}
            elif cmd == 'info':
                # binary静态信息
                from pwn import ELF
                elf = ELF(sess['binary'], checksec=False)
                return {'ok': True, 'info': {
                    'got_puts': hex(elf.got.get('puts', 0)),
                    'plt_puts': hex(elf.plt.get('puts', 0)),
                    'main': hex(elf.symbols.get('main', 0)),
                    'got_printf': hex(elf.got.get('printf', 0)),
                    'plt_printf': hex(elf.plt.get('printf', 0)),
                    'got_read': hex(elf.got.get('read', 0)),
                    'plt_read': hex(elf.plt.get('read', 0)),
                }}
            elif cmd == 'maps':
                # 读取进程内存映射(验证libc基址)
                pid = p.pid if hasattr(p, 'pid') else None
                if not pid:
                    return {'error': 'no pid'}
                with open(f'/proc/{pid}/maps', 'r') as f:
                    maps = f.read()
                libc_lines = [l for l in maps.splitlines() if 'libc' in l][:4]
                return {'ok': True, 'pid': pid, 'libc_maps': libc_lines}
            elif cmd == 'pid':
                pid = p.pid if hasattr(p, 'pid') else None
                return {'ok': True, 'pid': pid}
            else:
                return {'error': f'unknown cmd: {cmd}'}
        except Exception as e:
            # 异常详情仅日志, 不泄露内部路径
            print(f'[pwn-web] cmd error: {type(e).__name__}: {e}', flush=True)
            return {'error': 'command failed'}

TASKS = TaskManager()
INTERACT = InteractManager()

# ============ HTTP Handler ============
class Handler(BaseHTTPRequestHandler):
    timeout = HANDLER_TIMEOUT  # 慢连接防线程挂死
    
    def log_message(self, fmt, *args):
        pass  # 静默
    
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    
    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError(f'body too large (>{MAX_BODY})')
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode('utf-8'))
        except:
            return {'raw': raw.decode('latin-1', 'replace')}
    
    def do_GET(self):
        path = self.path.split('?')[0]
        if TOKEN and self.headers.get('X-Token') != TOKEN:
            self._json({'error': 'unauthorized'}, 401)
            return
        try:
            if path == '/status':
                self._json({'ok': True, 'status': 'alive', 'tasks': len(TASKS.tasks),
                            'sessions': len(INTERACT.sessions), 'time': time.time()})
            elif path.startswith('/solve/'):
                tid = path.split('/')[-1]
                t = TASKS.get(tid)
                if not t:
                    self._json({'error': 'task not found'}, 404)
                else:
                    self._json({'task_id': tid, **t})
            elif path.startswith('/interact/'):
                sid = path.split('/')[-1]
                with INTERACT.lock:
                    sess = INTERACT.sessions.get(sid)
                    if not sess:
                        self._json({'error': 'session not found'}, 404)
                    elif time.time() - sess.get('last_active', 0) > SESSION_TTL:
                        # 空闲TTL回收
                        try:
                            sess['proc'].close()
                        except:
                            pass
                        INTERACT.sessions.pop(sid, None)
                        self._json({'error': 'session expired'}, 404)
                    else:
                        sess['last_active'] = time.time()  # 轮询刷新空闲时间
                        out = sess['output'].decode('latin-1', 'replace')
                        self._json({'sid': sid, 'output': out[-8000:], 'closed': sess['closed'],
                                    'poll': sess['proc'].poll()})
            else:
                self._json({'error': 'not found', 'usage': 'GET /status, POST /solve, POST /interact, GET /solve/<id>, GET /interact/<sid>'}, 404)
        except Exception as e:
            # 不泄露内部细节(类型/路径等), 详情仅打印到服务日志
            print(f'[pwn-web] error: {type(e).__name__}: {e}', flush=True)
            self._json({'error': 'internal error'}, 500)
    
    def do_POST(self):
        path = self.path.split('?')[0]
        if TOKEN and self.headers.get('X-Token') != TOKEN:
            self._json({'error': 'unauthorized'}, 401)
            return
        try:
            body = self._read_body()
            if path == '/solve':
                binary = body.get('binary')
                if not binary:
                    self._json({'error': 'binary required'}, 400)
                    return
                libc = body.get('libc')
                timeout = min(max(int(body.get('timeout') or 60), 1), MAX_TIMEOUT)
                tid = TASKS.submit(binary, libc, timeout)
                self._json({'ok': True, 'task_id': tid, 'poll': f'/solve/{tid}'})
            elif path == '/interact':
                binary = body.get('binary')
                cmd = body.get('cmd')
                if cmd == 'start':
                    if not binary:
                        self._json({'error': 'binary required'}, 400)
                        return
                    sid, err = INTERACT.start(binary)
                    if err:
                        self._json({'ok': False, 'error': err}, 500)
                    else:
                        self._json({'ok': True, 'sid': sid, 'poll': f'/interact/{sid}'})
                elif cmd:
                    sid = body.get('sid')
                    if not sid:
                        self._json({'error': 'sid required'}, 400)
                        return
                    data = body.get('data')
                    result = INTERACT.cmd(sid, cmd, data)
                    self._json(result)
                else:
                    self._json({'error': 'cmd required'}, 400)
            else:
                self._json({'error': 'not found'}, 404)
        except Exception as e:
            # 不泄露内部细节(类型/路径等), 详情仅打印到服务日志
            print(f'[pwn-web] error: {type(e).__name__}: {e}', flush=True)
            self._json({'error': 'internal error'}, 500)

if __name__ == '__main__':
    print(f"[pwn-web] 启动 http://localhost:{PORT}", flush=True)
    print(f"[pwn-web] API: /status  /solve  /interact", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pwn-web] 停止", flush=True)
