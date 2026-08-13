#!/usr/bin/env python3
"""
PwnSolver GUI v2 — 自动PWN解题器前端
支持: WSL/本机解题、自适应求解器、交互Shell、exp管理、代码审计
"""

import subprocess, sys, os, threading, json, time, re, shlex, datetime
from pathlib import Path

def sanitize(text):
    """移除不可打印字符"""
    return re.sub(r'[^\x20-\x7e\u4e00-\u9fff\u3000-\u303f\uff00-\uffef\n\r\t]', '', text)

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
except ImportError:
    print("tkinter not found! Install: pip install tk")
    sys.exit(1)

# ========= 路径与执行环境 =========
def to_wsl_path(win_path):
    """C:\\Users\\... → /mnt/c/Users/... (Linux 路径原样返回)"""
    p = win_path.replace('\\', '/')
    if ':' in p:
        drive, rest = p.split(':', 1)
        p = f'/mnt/{drive.lower()}{rest}'
    return p

IS_WINDOWS = sys.platform == 'win32'

def exec_prefix():
    """Windows 上经 wsl 执行; 在 WSL/Linux 内直接执行"""
    return ['wsl', 'bash', '-c'] if IS_WINDOWS else ['bash', '-c']

def open_path(path):
    """跨平台打开文件/文件夹"""
    if IS_WINDOWS:
        os.startfile(path)
    else:
        subprocess.Popen(['xdg-open', path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 彩虹色 (成功命令着色用)
RAINBOW_COLORS = ['#f38ba8', '#fab387', '#f9e2af', '#a6e3a1', '#89b4fa', '#cba6f7']

def classify_line(line):
    """按内容给日志行分类 → tag (纯函数, 便于测试)

    返回: 'success' | 'error' | 'warning' | 'bold' | 'shell' | 'cmd' | None
    cmd = 命令回显行 ($ 开头), 独立于普通 shell 输出以便着色区分
    """
    if line.startswith('$ ') or line.startswith('$'):
        return 'cmd'
    line_lower = line.lower()
    if any(k in line for k in ['成功', 'success', '★', 'solved', '✅']):
        return 'success'
    if any(k in line for k in ['失败', 'error', '✗', '❌']):
        return 'error'
    if any(k in line for k in ['⚠', 'warning', '警告']):
        return 'warning'
    if any(k in line for k in ['📋', '①', '决策', '阶段', 'gadgets', 'seccomp']):
        return 'bold'
    if any(k in line for k in ['$', '#', '>>>', 'uid=', 'interactive']):
        return 'shell'
    return None

def kill_process_tree(proc):
    """杀掉进程树 (bash -c 包装下需连同子进程)"""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:
        pass

def build_solve_cmd(workspace, binary, libc='', ld='', remote_host='',
                    remote_port='', timeout=120, adaptive=True):
    """构建 solver 命令 (纯函数, 便于测试)"""
    args = ['python3', '-W', 'ignore', 'pwn_solver/solver.py', binary]
    if libc:
        args += ['-l', libc]
    if ld:
        args += ['-d', ld]
    if remote_host and remote_port:
        args += ['-r', remote_host, str(remote_port)]
    args += ['-t', str(timeout)]
    if not adaptive:
        args += ['--no-adaptive']
    return f"cd {shlex.quote(workspace)} && " + ' '.join(shlex.quote(a) for a in args)

WORKSPACE = to_wsl_path(str(Path(__file__).parent))
EXPLOITS_DIR = os.path.join(str(Path(__file__).parent), 'exploits')
os.makedirs(EXPLOITS_DIR, exist_ok=True)

# ========= 主窗口 =========
class PwnSolverGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PwnSolver v2 — 自适应PWN解题器")
        self.root.geometry("1000x750")
        self.root.configure(bg='#1e1e2e')
        
        self.solver_script = f'{WORKSPACE}/pwn_solver/solver.py'
        self._killed = False
        self._shell_proc = None      # 交互shell进程
        self._solve_proc = None      # 当前解题进程 (用于停止)
        self._last_exploit_path = None
        self._last_cmd_start = None  # 最后一条命令回显行的起始 index (成功时彩虹着色)
        
        self._build_ui()
        self.log("PwnSolver GUI v2 已启动", 'info')
        self.log('选择binary → 开始解题 → 成功后可交互Shell', 'info')
        self._refresh_exp_list()
    
    def _build_ui(self):
        # === 顶部标题 ===
        header = tk.Frame(self.root, bg='#2d2d44', height=45)
        header.pack(fill='x')
        tk.Label(header, text="🔧 PwnSolver v2 — 自适应PWN解题框架",
                font=('Consolas', 13, 'bold'), fg='#cdd6f4', bg='#2d2d44',
                pady=8).pack()
        
        # === 配置区 ===
        cfg_frame = tk.Frame(self.root, bg='#1e1e2e', pady=8)
        cfg_frame.pack(fill='x', padx=20)
        
        # 行1: Binary + Libc
        row1 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row1.pack(fill='x')
        tk.Label(row1, text="📦 Binary:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.binary_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.binary_var, width=55,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=1, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_binary,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=2)
        
        tk.Label(row1, text="📚 Libc:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=3, sticky='w', padx=(20,0), pady=3)
        self.libc_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.libc_var, width=25,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=4, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_libc,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=5)
        tk.Label(row1, text="📎 LD:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=6, sticky='w', padx=(20,0), pady=3)
        self.ld_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.ld_var, width=20,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=7, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_ld,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=8)
        
        # 行2: Remote Host + Port + Timeout + 选项
        row2 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row2.pack(fill='x', pady=(5,0))
        
        tk.Label(row2, text="🌐 Host:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.remote_host_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.remote_host_var, width=22,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=1, padx=3, sticky='w')
        
        tk.Label(row2, text="🔌 Port:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=2, sticky='w', padx=(3,0))
        self.remote_port_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.remote_port_var, width=7,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=3, padx=3, sticky='w')
        
        tk.Label(row2, text="⏱ 超时:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=4, sticky='w', padx=(10,0))
        self.timeout_var = tk.StringVar(value='120')
        tk.Entry(row2, textvariable=self.timeout_var, width=6,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=5, padx=3, sticky='w')
        
        # 自适应求解器选项 + 成功自动Shell
        self.adaptive_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row2, text="🔁 自适应", variable=self.adaptive_var,
                bg='#1e1e2e', fg='#a6e3a1', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#a6e3a1').grid(row=0, column=4, padx=(20,0))
        self.auto_shell_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="💻 成功后自动Shell", variable=self.auto_shell_var,
                bg='#1e1e2e', fg='#cba6f7', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#cba6f7').grid(row=0, column=5, padx=(10,0))
        
        # 行3: 自定义命令执行
        row3 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row3.pack(fill='x', pady=(5,0))
        tk.Label(row3, text="⌨ 自定义命令:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.custom_cmd_var = tk.StringVar()
        self.custom_cmd_entry = tk.Entry(row3, textvariable=self.custom_cmd_var, width=75,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9))
        self.custom_cmd_entry.grid(row=0, column=1, padx=5)
        self.custom_cmd_entry.bind('<Return>', lambda e: self._run_custom())
        tk.Button(row3, text="▶ 执行", command=self._run_custom,
                bg='#89b4fa', fg='#1e1e2e', relief='flat', cursor='hand2',
                font=('Consolas', 9, 'bold')).grid(row=0, column=2, padx=3)
        tk.Label(row3, text="(bash 语法, 输出流式进日志)", fg='#6c7086', bg='#1e1e2e',
                font=('Consolas', 8)).grid(row=0, column=3, sticky='w', padx=5)
        
        # === 按钮区 ===
        btn_frame = tk.Frame(self.root, bg='#1e1e2e', pady=8)
        btn_frame.pack(fill='x', padx=20)
        
        self.solve_btn = tk.Button(btn_frame, text="🚀 开始解题",
                command=self._start_solve,
                bg='#89b4fa', fg='#1e1e2e', font=('Consolas', 11, 'bold'),
                relief='flat', padx=25, pady=6, cursor='hand2')
        self.solve_btn.pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="📋 代码审计",
                command=self._run_audit,
                bg='#a6e3a1', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="🔍 偏移检测",
                command=self._run_offset,
                bg='#fab387', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        # Shell按钮
        self.shell_btn = tk.Button(btn_frame, text="💻 交互Shell",
                command=self._open_interactive_shell,
                bg='#cba6f7', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2', state='disabled')
        self.shell_btn.pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="📁 Exp文件夹",
                command=self._open_exp_folder,
                bg='#45475a', fg='#cdd6f4', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="🗑 清空日志",
                command=lambda: self.output.delete(1.0, tk.END),
                bg='#45475a', fg='#cdd6f4', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹ 停止",
                command=self._stop_solve,
                bg='#f38ba8', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2')
        self.stop_btn.pack(side='left', padx=3)
        
        # 进度条
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill='x', padx=20, pady=3)
        
        # === 双面板: 输出 + exp列表 ===
        paned = tk.PanedWindow(self.root, orient='horizontal',
                               bg='#1e1e2e', sashrelief='flat')
        paned.pack(fill='both', expand=True, padx=20, pady=5)
        
        # 左: 输出区
        left = tk.Frame(paned, bg='#1e1e2e')
        tk.Label(left, text="📄 输出日志:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        self.output = scrolledtext.ScrolledText(left,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='word',
                relief='flat', borderwidth=0)
        self.output.pack(fill='both', expand=True)
        
        # 颜色标签
        self.output.tag_configure('success', foreground='#a6e3a1')
        self.output.tag_configure('error', foreground='#f38ba8')
        self.output.tag_configure('warning', foreground='#fab387')
        self.output.tag_configure('info', foreground='#89b4fa')
        self.output.tag_configure('bold', foreground='#cdd6f4', font=('Consolas', 10, 'bold'))
        self.output.tag_configure('shell', foreground='#cba6f7')
        self.output.tag_configure('cmd', foreground='#f9e2af', font=('Consolas', 10, 'bold'))
        self.output.tag_configure('cmd_success', foreground='#a6e3a1', font=('Consolas', 10, 'bold'))
        for i, color in enumerate(RAINBOW_COLORS):
            self.output.tag_configure(f'rainbow{i}', foreground=color)
        
        # 右: exp列表 + shell输入
        right = tk.Frame(paned, bg='#1e1e2e', width=280)
        
        tk.Label(right, text="📁 Exploits:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        self.exp_listbox = tk.Listbox(right,
                bg='#11111b', fg='#cdd6f4',
                font=('Consolas', 9), relief='flat', borderwidth=0,
                selectbackground='#45475a', selectforeground='#cdd6f4')
        self.exp_listbox.pack(fill='both', expand=True, pady=(0,5))
        self.exp_listbox.bind('<Double-Button-1>', self._open_selected_exp)
        # 右键菜单: 打开 / 复制路径 / 删除 / 刷新
        self.exp_menu = tk.Menu(self.root, tearoff=0,
                                bg='#313244', fg='#cdd6f4',
                                activebackground='#45475a', activeforeground='#cdd6f4')
        self.exp_menu.add_command(label="打开", command=self._open_selected_exp)
        self.exp_menu.add_command(label="复制路径", command=self._copy_exp_path)
        self.exp_menu.add_command(label="删除", command=self._delete_selected_exp)
        self.exp_menu.add_separator()
        self.exp_menu.add_command(label="刷新", command=self._refresh_exp_list)
        self.exp_listbox.bind('<Button-3>', self._show_exp_menu)
        
        # Shell快速输入
        tk.Label(right, text="💻 快速Shell:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        shell_frame = tk.Frame(right, bg='#1e1e2e')
        shell_frame.pack(fill='x')
        self.shell_input = tk.Entry(shell_frame,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9))
        self.shell_input.pack(side='left', fill='x', expand=True, padx=(0,3))
        self.shell_input.bind('<Return>', self._send_shell_command)
        tk.Button(shell_frame, text="发送", command=self._send_shell_command,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).pack(side='right')
        
        paned.add(left, stretch='always')
        paned.add(right, stretch='never')
        
        # 底部状态栏
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(self.root, textvariable=self.status_var, anchor='w',
                bg='#2d2d44', fg='#a6adc8',
                font=('Consolas', 8), padx=10, pady=2).pack(fill='x', side='bottom')
    
    # ========== 日志 ==========
    def log(self, msg, tag=None):
        self.output.insert(tk.END, msg + '\n', tag)
        self.output.see(tk.END)
        self.root.update_idletasks()
    
    def _log_line(self, line):
        tag = classify_line(line)
        self.log(line, tag)
    
    def log_cmd(self, cmd):
        """记录命令回显行 (金色加粗), 返回行起始 index 供成功后彩虹着色"""
        start = self.output.index('end-1c linestart')
        self.log(f"$ {cmd}", 'cmd')
        self._last_cmd_start = start
        return start
    
    def _mark_rainbow(self, start_index):
        """把 start_index 起的命令回显行逐字符染成彩虹色 (6 色循环)"""
        try:
            line_end = self.output.index(f'{start_index} lineend')
            text = self.output.get(start_index, line_end)
            for ch_idx in range(len(text)):
                tag = f'rainbow{ch_idx % len(RAINBOW_COLORS)}'
                self.output.tag_add(tag, f'{start_index}+{ch_idx}c',
                                    f'{start_index}+{ch_idx + 1}c')
        except Exception:
            pass
    
    def _log_stderr(self, text):
        text = sanitize(text)[:2000]
        if text.strip():
            self.log("[stderr]:", 'warning')
            self.log(text, 'warning')
    
    # ========== 文件浏览 ==========
    def _browse_binary(self):
        f = filedialog.askopenfilename(title="选择Binary文件")
        if f:
            self.binary_var.set(f)
            # 自动检测同目录libc
            d = os.path.dirname(f)
            for name in ['libc.so.6', 'libc-2.31.so', 'libc-2.27.so', 'libc.so']:
                candidate = os.path.join(d, name)
                if os.path.exists(candidate):
                    self.libc_var.set(candidate)
                    self.log(f"🔍 自动检测到libc: {name}", 'info')
                    break
    
    def _browse_libc(self):
        f = filedialog.askopenfilename(title="选择libc文件")
        if f:
            self.libc_var.set(f)

    def _browse_ld(self):
        f = filedialog.askopenfilename(title="选择ld-linux加载器文件")
        if f:
            self.ld_var.set(f)
    
    # ========== 执行 ==========
    def _run_stream(self, cmd, timeout=60):
        """流式运行命令 (Windows 经 wsl, WSL 内直接执行)"""
        self._killed = False
        self._solve_proc = None
        full_cmd = exec_prefix() + ['ulimit -c 0 2>/dev/null; ' + cmd]
        try:
            proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   encoding='utf-8', errors='replace')
            self._solve_proc = proc
        except Exception as e:
            self.root.after(0, lambda: self.log(f"[启动失败] {e}", 'error'))
            return -1
        
        stderr_lines = []
        
        def read_stdout():
            for line in iter(proc.stdout.readline, ''):
                if self._killed:
                    return
                line = sanitize(line.rstrip('\n'))
                if line:
                    self.root.after(0, lambda l=line: self._log_line(l))
        
        def read_stderr():
            for line in iter(proc.stderr.readline, ''):
                if self._killed:
                    return
                stderr_lines.append(line)
        
        t1 = threading.Thread(target=read_stdout, daemon=True)
        t2 = threading.Thread(target=read_stderr, daemon=True)
        t1.start(); t2.start()
        
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._killed = True
            kill_process_tree(proc)
            self.log("\n⏰ 超时!", 'error')
        
        t1.join(timeout=3); t2.join(timeout=3)
        
        if stderr_lines:
            self.root.after(0, lambda: self._log_stderr(''.join(stderr_lines)))
        
        return proc.returncode
    
    # ========== 解题流程 ==========
    def _start_solve(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        
        wsl_binary = to_wsl_path(binary)
        libc = self.libc_var.get().strip()
        ld = self.ld_var.get().strip() if hasattr(self, 'ld_var') else ''
        timeout = self.timeout_var.get().strip() or '120'
        remote_host = self.remote_host_var.get().strip()
        remote_port = self.remote_port_var.get().strip()
        
        self.log(f"\n{'='*60}", 'bold')
        self.log(f"🎯 目标: {os.path.basename(binary)}", 'bold')
        self.log(f"🔁 自适应: {'开' if self.adaptive_var.get() else '关'}", 'info')
        if remote_host:
            self.log(f"🌐 远程: {remote_host}:{remote_port}", 'info')
        self.log(f"{'='*60}", 'bold')
        
        # 验证输入
        try:
            timeout_int = int(timeout)
        except ValueError:
            messagebox.showerror("错误", "超时必须是数字!")
            return
        
        if remote_host and remote_port:
            try:
                port_int = int(remote_port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showerror("错误", "端口必须是 1-65535 的数字!")
                return
        
        cmd = build_solve_cmd(
            WORKSPACE, wsl_binary,
            libc=to_wsl_path(libc) if libc else '',
            ld=to_wsl_path(ld) if ld else '',
            remote_host=remote_host if remote_host else '',
            remote_port=remote_port if remote_port else '',
            timeout=timeout_int,
            adaptive=self.adaptive_var.get(),
        )
        self.log_cmd(cmd)
        
        self.solve_btn.config(state='disabled', text="⏳ 解题中...")
        self.shell_btn.config(state='disabled')
        self.progress.start(12)
        self.status_var.set("解题中...")
        
        def worker():
            rc = self._run_stream(cmd, timeout=timeout_int + 120)
            self.root.after(0, lambda: self._on_solve_done(rc))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_solve_done(self, rc):
        self.progress.stop()
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self._cleanup_cores()
        if rc == 0:
            # 成功的命令回显 → 彩虹色 (与普通输出区分)
            if self._last_cmd_start is not None:
                self._mark_rainbow(self._last_cmd_start)
            self.log("\n✅ 解题成功! 点击 💻交互Shell 获取shell", 'success')
            self.shell_btn.config(state='normal', bg='#cba6f7')
            self.status_var.set("解题成功")
            if self.auto_shell_var.get():
                self.root.after(200, self._open_interactive_shell)
        elif rc is not None:
            self.log(f"\n❌ 退出码: {rc}", 'error')
            self.status_var.set(f"解题失败 (rc={rc})")
        else:
            self.log("\n⏰ 超时", 'error')
            self.status_var.set("解题超时")
        self._refresh_exp_list()
    
    # ========== 代码审计 / 偏移 ==========
    def _run_audit(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self.log(f"\n📋 代码审计: {os.path.basename(binary)}", 'bold')
        code = (f"from pwn_solver.code_auditor import audit_binary; "
                f"audit_binary({to_wsl_path(binary)!r})")
        cmd = (f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
               f"{shlex.quote(code)}")
        threading.Thread(target=lambda: self._run_stream(cmd, 60), daemon=True).start()
    
    def _run_offset(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self.log(f"\n🔍 偏移检测: {os.path.basename(binary)}", 'bold')
        code = (f"from pwn_solver.gdb_debugger import GdbDebugger; "
                f"g=GdbDebugger({to_wsl_path(binary)!r}); "
                f"print('offset:', g.find_offset())")
        cmd = (f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
               f"{shlex.quote(code)}")
        threading.Thread(target=lambda: self._run_stream(cmd, 30), daemon=True).start()
    
    # ========== 自定义命令 ==========
    def _run_custom(self):
        cmd = self.custom_cmd_var.get().strip()
        if not cmd:
            messagebox.showerror("错误", "请输入要执行的命令!")
            return
        self.log(f"\n{'='*50}", 'bold')
        self.log("⌨ 自定义命令执行", 'bold')
        self.log(f"{'='*50}", 'bold')
        self.log_cmd(cmd)
        self.status_var.set("命令执行中...")
        self.progress.start(12)
        self.solve_btn.config(state='disabled', text="⏳ 执行中...")
        
        def worker():
            rc = self._run_stream(cmd, timeout=300)
            self.root.after(0, lambda: self._on_custom_done(rc))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_custom_done(self, rc):
        self.progress.stop()
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        if rc == 0:
            if self._last_cmd_start is not None:
                self._mark_rainbow(self._last_cmd_start)
            self.log(f"\n✅ 命令执行成功 (rc={rc})", 'success')
            self.status_var.set("命令执行成功")
        else:
            self.log(f"\n❌ 命令执行失败 (rc={rc})", 'error')
            self.status_var.set(f"命令执行失败 (rc={rc})")
    
    # ========== 停止 ==========
    def _stop_solve(self):
        self._killed = True
        self.progress.stop()
        if self._solve_proc:
            kill_process_tree(self._solve_proc)
            self._solve_proc = None
        if self._shell_proc:
            kill_process_tree(self._shell_proc)
            self._shell_proc = None
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self.shell_btn.config(state='normal', text="💻 交互Shell")
        self.status_var.set("已停止")
        self._cleanup_cores()
        self.log("\n⏹ 已停止", 'warning')
    
    def _cleanup_cores(self):
        """清理core dump文件 (经执行前缀)"""
        try:
            subprocess.run(exec_prefix() +
                ['rm -f core core.* cores/core.* 2>/dev/null; echo ok'],
                capture_output=True, timeout=5)
        except Exception:
            pass
    
    # ========== 交互Shell ==========
    def _open_interactive_shell(self):
        """在GUI中打开交互shell"""
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        
        # 找最新的exp文件
        exp_path = self._find_latest_exp()
        if not exp_path:
            # 没有exp时，尝试用solver生成
            self.log("\n⚠ 未找到exp文件，尝试用solver生成...", 'warning')
            self._start_solve()
            return
        
        wsl_exp = to_wsl_path(exp_path)
        self.log(f"\n{'='*50}", 'bold')
        self.log(f"💻 启动交互Shell: {os.path.basename(exp_path)}", 'bold')
        self.log(f"   输入命令后按回车发送 | 输入 exit 退出", 'info')
        self.log(f"{'='*50}", 'bold')
        
        # 远程模式: 注入环境变量
        remote_host = self.remote_host_var.get().strip()
        remote_port = self.remote_port_var.get().strip()
        env_prefix = ""
        if remote_host and remote_port:
            env_prefix = f"PWN_REMOTE_HOST={shlex.quote(remote_host)} PWN_REMOTE_PORT={shlex.quote(remote_port)} "
            self.log(f"🌐 远程目标: {remote_host}:{remote_port}", 'info')
        
        # 在后台运行exp
        cmd = f"cd {shlex.quote(WORKSPACE)} && {env_prefix}python3 -W ignore {shlex.quote(wsl_exp)}"
        
        self.shell_btn.config(state='disabled', text="⏳ Shell运行中...")
        self._killed = False  # 重置
        
        # 使用Popen保持进程存活
        full_cmd = exec_prefix() + [cmd]
        try:
            self._shell_proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace'
            )
        except Exception as e:
            self.log(f"启动Shell失败: {e}", 'error')
            self.shell_btn.config(state='normal', text="💻 交互Shell")
            self.status_var.set("Shell启动失败")
            return
        
        # 读取stdout线程
        def read_shell():
            for line in iter(self._shell_proc.stdout.readline, ''):
                if self._killed:
                    return
                line = sanitize(line.rstrip('\n'))
                if line:
                    self.root.after(0, lambda l=line: self.log(l, 'shell'))
            # 进程结束
            self.root.after(0, self._on_shell_exit)
        
        threading.Thread(target=read_shell, daemon=True).start()
        self.shell_input.focus_set()
    
    def _send_shell_command(self, event=None):
        """发送命令到交互shell"""
        if not self._shell_proc or self._shell_proc.poll() is not None:
            self.log("Shell未运行", 'warning')
            return
        
        cmd = self.shell_input.get().strip()
        if not cmd:
            return
        
        self.shell_input.delete(0, tk.END)
        self.log(f"$ {cmd}", 'bold')
        
        try:
            self._shell_proc.stdin.write(cmd + '\n')
            self._shell_proc.stdin.flush()
        except Exception as e:
            self.log(f"发送失败: {e}", 'error')
    
    def _on_shell_exit(self):
        self.shell_btn.config(state='normal', text="💻 交互Shell")
        if self._shell_proc:
            kill_process_tree(self._shell_proc)
            self._shell_proc = None
        self.status_var.set("就绪")
        self.log("\n💻 Shell已退出", 'warning')
    
    # ========== Exp管理 ==========
    def _find_latest_exp(self):
        """找当前binary匹配的最新exp文件"""
        if not os.path.exists(EXPLOITS_DIR):
            return None
        binary = self.binary_var.get().strip()
        base = os.path.basename(binary) if binary else ""
        exps = sorted(
            [f for f in os.listdir(EXPLOITS_DIR) if f.endswith('.py')],
            key=lambda f: os.path.getmtime(os.path.join(EXPLOITS_DIR, f)),
            reverse=True
        )
        matching = [f for f in exps if base and base in f]
        return os.path.join(EXPLOITS_DIR, matching[0]) if matching else (
            os.path.join(EXPLOITS_DIR, exps[0]) if exps else None
        )
    
    def _refresh_exp_list(self):
        """刷新exp文件列表"""
        self.exp_listbox.delete(0, tk.END)
        if not os.path.exists(EXPLOITS_DIR):
            return
        exps = sorted(
            [f for f in os.listdir(EXPLOITS_DIR) if f.endswith('.py')],
            key=lambda f: os.path.getmtime(os.path.join(EXPLOITS_DIR, f)),
            reverse=True
        )
        for exp in exps:
            self.exp_listbox.insert(tk.END, exp)
    
    def _open_selected_exp(self, event=None):
        """双击/菜单打开选中的exp"""
        sel = self.exp_listbox.curselection()
        if sel:
            exp_name = self.exp_listbox.get(sel[0])
            exp_path = os.path.join(EXPLOITS_DIR, exp_name)
            open_path(exp_path)
    
    def _show_exp_menu(self, event):
        try:
            self.exp_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.exp_menu.grab_release()
    
    def _copy_exp_path(self):
        sel = self.exp_listbox.curselection()
        if sel:
            exp_path = os.path.join(EXPLOITS_DIR, self.exp_listbox.get(sel[0]))
            self.root.clipboard_clear()
            self.root.clipboard_append(exp_path)
            self.log(f"已复制路径: {exp_path}", 'info')
    
    def _delete_selected_exp(self):
        sel = self.exp_listbox.curselection()
        if not sel:
            return
        exp_path = os.path.join(EXPLOITS_DIR, self.exp_listbox.get(sel[0]))
        if messagebox.askyesno("删除", f"删除 {os.path.basename(exp_path)}?"):
            try:
                os.remove(exp_path)
                self.log(f"已删除: {os.path.basename(exp_path)}", 'warning')
            except Exception as e:
                self.log(f"删除失败: {e}", 'error')
            self._refresh_exp_list()
    
    def _open_exp_folder(self):
        """打开exp文件夹"""
        open_path(EXPLOITS_DIR)
    
    # ========== 主循环 ==========
    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    gui = PwnSolverGUI()
    gui.run()
