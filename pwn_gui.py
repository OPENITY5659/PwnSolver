#!/usr/bin/env python3
"""
PwnSolver GUI v2 — 自动PWN解题器前端
支持: WSL解题、自适应求解器、交互Shell、exp管理、代码审计
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

# ========= 路径工具 =========
def to_wsl_path(win_path):
    """C:\\Users\\... → /mnt/c/Users/..."""
    p = win_path.replace('\\', '/')
    if ':' in p:
        drive, rest = p.split(':', 1)
        p = f'/mnt/{drive.lower()}{rest}'
    return p

PROJECT_ROOT = Path(__file__).parent
WORKSPACE = to_wsl_path(str(PROJECT_ROOT))
EXPLOITS_DIR = PROJECT_ROOT / 'exploits'
EXPLOITS_DIR.mkdir(exist_ok=True)
EXPLOITS_DIR = str(EXPLOITS_DIR)

IS_WINDOWS = (os.name == 'nt')
IS_MACOS = (sys.platform == 'darwin')
IS_ARM64 = (IS_MACOS and os.uname().machine.lower() in ('arm64', 'aarch64')) if IS_MACOS else False
X86_IMAGE = os.environ.get('PWNSOLVER_X86_IMAGE', 'pwnsolver-x86:latest')

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
        self._last_playbook = None
        self._use_x86_sandbox = IS_ARM64

        self._build_ui()
        self.log("PwnSolver GUI v2 已启动", 'info')
        self.log('选择binary → 开始解题 → 成功后可交互Shell', 'info')
        self._refresh_exp_list()
        report = self._find_latest_report()
        if report:
            self._last_playbook = str(report)
            self.log(f"📑 最新报告: {report}", 'info')
    
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

        tk.Label(row1, text="🧩 LD:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=1, column=0, sticky='w', pady=3)
        self.ld_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.ld_var, width=55,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=1, column=1, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_ld,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=1, column=2)

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
        
        # 自适应求解器选项
        self.adaptive_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row2, text="🔁 自适应", variable=self.adaptive_var,
                bg='#1e1e2e', fg='#a6e3a1', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#a6e3a1').grid(row=0, column=4, padx=(20,0))

        # 第 3 行: reverse-skill / 沙盒选项
        row3 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row3.pack(fill='x', pady=(5, 0))
        self.skill_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row3, text="🛰 reverse-skill 增强", variable=self.skill_var,
                bg='#1e1e2e', fg='#89b4fa', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#89b4fa').pack(side='left')
        self.recon_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row3, text="🔎 仅侦察", variable=self.recon_var,
                bg='#1e1e2e', fg='#fab387', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#fab387').pack(side='left', padx=(10, 0))
        if IS_ARM64:
            self.sandbox_var = tk.BooleanVar(value=True)
            tk.Checkbutton(row3, text="🐳 x86_64 沙盒", variable=self.sandbox_var,
                    bg='#1e1e2e', fg='#a6e3a1', selectcolor='#313244',
                    font=('Consolas', 9), activebackground='#1e1e2e',
                    activeforeground='#a6e3a1').pack(side='left', padx=(10, 0))
        else:
            self.sandbox_var = tk.BooleanVar(value=False)
        
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

        tk.Button(btn_frame, text="📑 查看报告",
                command=self._open_latest_report,
                bg='#94e2d5', fg='#1e1e2e', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)

        tk.Button(btn_frame, text="🩺 环境自检",
                command=self._run_env_check,
                bg='#f9e2af', fg='#1e1e2e', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)

        if IS_ARM64:
            self.build_btn = tk.Button(btn_frame, text="🐳 构建沙盒",
                command=self._build_x86_image,
                bg='#cba6f7', fg='#1e1e2e', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2')
            self.build_btn.pack(side='left', padx=3)
        
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
    
    # ========== 日志 ==========
    def log(self, msg, tag=None):
        self.output.insert(tk.END, msg + '\n', tag)
        self.output.see(tk.END)
        self.root.update_idletasks()
    
    def _log_line(self, line):
        line_lower = line.lower()
        if any(k in line for k in ['成功', 'success', '★', 'solved', '✅']):
            self.log(line, 'success')
        elif any(k in line for k in ['失败', 'error', '✗', '❌']):
            self.log(line, 'error')
        elif any(k in line for k in ['⚠', 'warning', '警告']):
            self.log(line, 'warning')
        elif any(k in line for k in ['📋', '①', '决策', '阶段', 'gadgets', 'seccomp']):
            self.log(line, 'bold')
        elif any(k in line for k in ['$', '#', '>>>', 'uid=', 'interactive']):
            self.log(line, 'shell')
        else:
            self.log(line)
    
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
            # 自动检测同目录 libc / ld
            d = os.path.dirname(f)
            for name in ['libc.so.6', 'libc-2.31.so', 'libc-2.27.so', 'libc.so']:
                candidate = os.path.join(d, name)
                if os.path.exists(candidate):
                    self.libc_var.set(candidate)
                    self.log(f"🔍 自动检测到libc: {name}", 'info')
                    break
            try:
                for name in os.listdir(d):
                    if 'ld-linux' in name.lower() or (name.startswith('ld-') and 'linux' in name.lower()):
                        self.ld_var.set(os.path.join(d, name))
                        self.log(f"🔍 自动检测到ld: {name}", 'info')
                        break
            except OSError:
                pass
    
    def _browse_libc(self):
        f = filedialog.askopenfilename(title="选择libc文件")
        if f:
            self.libc_var.set(f)
            d = os.path.dirname(f)
            try:
                for name in os.listdir(d):
                    if 'ld-linux' in name.lower():
                        self.ld_var.set(os.path.join(d, name))
                        break
            except OSError:
                pass
    
    def _browse_ld(self):
        f = filedialog.askopenfilename(title="选择ld-linux加载器")
        if f:
            self.ld_var.set(f)

    # ========== 跨平台执行后端 ==========
    def _backend_path(self, path):
        """把用户选择的宿主机路径映射到执行后端。"""
        if not path:
            return path
        if IS_WINDOWS:
            return to_wsl_path(path)
        if IS_MACOS and self.sandbox_var.get():
            # Docker sandbox 挂载文件所在目录到 /ctf0, /ctf1...
            d = os.path.dirname(os.path.abspath(path))
            idx = self._sandbox_mount_index(d)
            return f'/ctf{idx}/{os.path.basename(path)}'
        return path

    def _sandbox_mounts(self):
        """为 binary/libc/ld 所在目录生成不重复挂载。"""
        mounts, dirs = [], []
        for p in (self.binary_var.get().strip(), self.libc_var.get().strip(), self.ld_var.get().strip()):
            if not p or IS_WINDOWS:
                continue
            d = os.path.dirname(os.path.abspath(p))
            if d not in dirs:
                dirs.append(d)
                mounts.append((d, f'/ctf{len(mounts)}'))
        self._sandbox_dirs = dirs
        return mounts

    def _sandbox_mount_index(self, d):
        for i, existing in enumerate(getattr(self, '_sandbox_dirs', [])):
            if os.path.abspath(d) == os.path.abspath(existing):
                return i
        return 0

    def _run_stream(self, cmd, timeout=60, cwd=None):
        """流式执行：Windows->WSL，macOS ARM->x86 Docker sandbox，其他->本机。"""
        self._killed = False
        self._solve_proc = None

        full_cmd = self._build_stream_command(cmd, cwd=cwd)

        try:
            proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   encoding='utf-8', errors='replace', cwd=cwd)
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
            proc.kill(); proc.wait()
            self.log("\n⏰ 超时!", 'error')
        t1.join(timeout=3); t2.join(timeout=3)
        if stderr_lines:
            self.root.after(0, lambda: self._log_stderr(''.join(stderr_lines)))
        return proc.returncode

    def _build_stream_command(self, cmd, cwd=None):
        """仅构造后端命令，供 _run_stream 和交互 Shell 复用。"""
        if IS_WINDOWS:
            return ['wsl', 'bash', '-c', cmd]
        if IS_MACOS and self.sandbox_var.get():
            mounts = self._sandbox_mounts()
            docker_args = []
            for host_dir, container_dir in mounts:
                docker_args += ['-v', f'{host_dir}:{container_dir}']
            docker_args += ['-v', f'{PROJECT_ROOT}:/pwnsolver']
            workdir = mounts[0][1] if mounts else '/pwnsolver'
            return [
                'docker', 'run', '--platform', 'linux/amd64', '--rm', '-i',
                '--cap-add=SYS_PTRACE', '--security-opt', 'seccomp=unconfined',
                *docker_args, '-w', workdir,
                '-e', 'PWNSOLVER_X86=1', '-e', 'PYTHONUNBUFFERED=1',
                X86_IMAGE, 'bash', '-lc', cmd,
            ]
        return ['bash', '-lc', cmd]

    def _run_wsl_stream(self, cmd, timeout=60):
        # 兼容旧调用名
        return self._run_stream(cmd, timeout=timeout)

    def _run_env_check(self):
        """运行 check_env.py 并输出工具链状态。"""
        self.log("\n🩺 环境自检...", 'bold')
        if IS_MACOS and self.sandbox_var.get():
            cmd = "cd /pwnsolver && python3 check_env.py"
        else:
            cmd = f"cd {WORKSPACE} && python3 check_env.py"
        threading.Thread(target=lambda: self._run_stream(cmd, 60), daemon=True).start()

    def _build_x86_image(self):
        """调用 scripts/pwn-x86-build 构建 amd64 镜像。"""
        script = PROJECT_ROOT / 'scripts' / 'pwn-x86-build'
        self.log(f"\n🐳 构建 {X86_IMAGE} ...", 'bold')
        def worker():
            try:
                proc = subprocess.Popen([str(script)], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True,
                                       encoding='utf-8', errors='replace')
                for line in iter(proc.stdout.readline, ''):
                    line = sanitize(line.rstrip('\n'))
                    if line:
                        self.root.after(0, lambda l=line: self.log(l))
                proc.wait(timeout=1800)
                self.root.after(0, lambda: self.log("🐳 沙盒镜像构建完成", 'success'))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"🐳 构建失败: {e}", 'error'))
        threading.Thread(target=worker, daemon=True).start()

    def _find_latest_report(self):
        """查找最新的 playbook/recon 报告。"""
        candidates = []
        base = Path(self.binary_var.get().strip()).parent if self.binary_var.get().strip() else PROJECT_ROOT
        evidence_dirs = [base / 'pwnsolver_evidence', PROJECT_ROOT / 'pwnsolver_evidence']
        for ev in evidence_dirs:
            if ev.exists():
                candidates += list(ev.rglob('*.playbook.md')) + list(ev.rglob('*.recon.md'))
        if not candidates:
            return None
        return max(candidates, key=lambda f: f.stat().st_mtime)

    def _open_latest_report(self):
        report = self._find_latest_report()
        if not report:
            self.log("\n📑 未找到报告。先执行 --recon-only 或完整解题。", 'warning')
            return
        self.log(f"\n📑 打开报告: {report}", 'info')
        self._open_with_platform_default(str(report))
    
    # ========== 解题流程 ==========
    def _start_solve(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        
        host_binary = binary
        host_libc = self.libc_var.get().strip()
        host_ld = self.ld_var.get().strip()
        timeout = self.timeout_var.get().strip() or '120'
        remote_host = self.remote_host_var.get().strip()
        remote_port = self.remote_port_var.get().strip()

        # 先刷新沙盒挂载，再映射宿主机路径
        if IS_MACOS and self.sandbox_var.get():
            self._sandbox_mounts()
        backend_binary = self._backend_path(host_binary)
        backend_libc = self._backend_path(host_libc) if host_libc else ''
        backend_ld = self._backend_path(host_ld) if host_ld else ''
        wsl_binary = shlex.quote(backend_binary)
        
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
        
        libc_arg = f"-l {shlex.quote(backend_libc)}" if backend_libc else ""
        ld_arg = f"-d {shlex.quote(backend_ld)}" if backend_ld else ""
        skill_arg = "" if self.skill_var.get() else "--no-skill"
        recon_arg = "--recon-only" if self.recon_var.get() else ""
        remote_arg = ""
        if remote_host and remote_port:
            try:
                port_int = int(remote_port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
                remote_arg = f"-r {shlex.quote(remote_host)} {shlex.quote(remote_port)}"
            except ValueError:
                messagebox.showerror("错误", "端口必须是 1-65535 的数字!")
                return
        
        cmd = (f"cd /pwnsolver && python3 -W ignore "
               f"pwn_solver/solver.py {wsl_binary} {libc_arg} {ld_arg} {remote_arg} "
               f"{skill_arg} {recon_arg} -t {timeout_int}")
        if not IS_MACOS or not self.sandbox_var.get():
            cmd = (f"cd {WORKSPACE} && python3 -W ignore "
                   f"pwn_solver/solver.py {wsl_binary} {libc_arg} {ld_arg} {remote_arg} "
                   f"{skill_arg} {recon_arg} -t {timeout_int}")
        
        self.solve_btn.config(state='disabled', text="⏳ 解题中...")
        self.shell_btn.config(state='disabled')
        
        def worker():
            rc = self._run_stream(cmd, timeout=timeout_int + 120)
            self.root.after(0, lambda: self._on_solve_done(rc))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_solve_done(self, rc):
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self._cleanup_cores()
        if rc == 0:
            self.log("\n✅ 解题成功! 点击 💻交互Shell 获取shell", 'success')
            self.shell_btn.config(state='normal', bg='#cba6f7')
        elif rc is not None:
            self.log(f"\n❌ 退出码: {rc}", 'error')
        else:
            self.log("\n⏰ 超时", 'error')
        self._refresh_exp_list()
    
    # ========== 代码审计 / 偏移 ==========
    def _run_audit(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        if IS_MACOS and self.sandbox_var.get(): self._sandbox_mounts()
        backend_binary = self._backend_path(binary)
        wsl_binary = shlex.quote(backend_binary)
        self.log(f"\n📋 代码审计: {os.path.basename(binary)}", 'bold')
        cmd = (f"cd /pwnsolver && python3 -W ignore -c "
               f"\"from pwn_solver.code_auditor import audit_binary; "
               f"audit_binary({wsl_binary})\"")
        threading.Thread(target=lambda: self._run_stream(cmd, 60), daemon=True).start()
    
    def _run_offset(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        if IS_MACOS and self.sandbox_var.get(): self._sandbox_mounts()
        backend_binary = self._backend_path(binary)
        wsl_binary = shlex.quote(backend_binary)
        self.log(f"\n🔍 偏移检测: {os.path.basename(binary)}", 'bold')
        cmd = (f"cd /pwnsolver && python3 -W ignore -c "
               f"\"from pwn_solver.gdb_debugger import GdbDebugger; "
               f"g=GdbDebugger({wsl_binary}); print('offset:', g.find_offset())\"")
        threading.Thread(target=lambda: self._run_stream(cmd, 30), daemon=True).start()
    
    # ========== 停止 ==========
    def _stop_solve(self):
        self._killed = True
        if self._solve_proc:
            try: self._solve_proc.kill()
            except: pass
            self._solve_proc = None
        if self._shell_proc:
            try: self._shell_proc.kill()
            except: pass
            self._shell_proc = None
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self.shell_btn.config(state='normal', text="💻 交互Shell")
        self._cleanup_cores()
        self.log("\n⏹ 已停止", 'warning')
    
    def _cleanup_cores(self):
        """清理 core dump 文件。"""
        try:
            if IS_WINDOWS:
                subprocess.run(['wsl', 'bash', '-c', 'rm -f core core.* cores/core.* 2>/dev/null'], capture_output=True, timeout=5)
            else:
                for f in list(Path.cwd().glob('core')) + list(Path.cwd().glob('core.*')):
                    try: f.unlink()
                    except Exception: pass
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
        
        if IS_MACOS and self.sandbox_var.get(): self._sandbox_mounts()
        backend_exp = self._backend_path(exp_path)
        wsl_exp = backend_exp
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
        cmd = f"cd /pwnsolver && {env_prefix}python3 -W ignore {shlex.quote(wsl_exp)}"
        if not IS_MACOS or not self.sandbox_var.get():
            cmd = f"cd {WORKSPACE} && {env_prefix}python3 -W ignore {shlex.quote(wsl_exp)}"
        
        self.shell_btn.config(state='disabled', text="⏳ Shell运行中...")
        self._killed = False  # 重置

        full_cmd = self._build_stream_command(cmd)
        if full_cmd is None:
            self.shell_btn.config(state='normal', text="💻 交互Shell")
            return
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
            try: self._shell_proc.kill()
            except: pass
            self._shell_proc = None
        self.log("\n💻 Shell已退出", 'warning')
    
    # ========== Exp管理 ==========
    def _find_latest_exp(self):
        """找当前binary匹配的最新exp文件"""
        if not os.path.exists(EXPLOITS_DIR):
            return None
        binary = self.binary_var.get().strip()
        base = os.path.basename(binary) if binary else ""
        # 优先匹配当前binary
        exps = sorted(
            [f for f in os.listdir(EXPLOITS_DIR) if f.endswith('.py')],
            key=lambda f: os.path.getmtime(os.path.join(EXPLOITS_DIR, f)),
            reverse=True
        )
        # 先找匹配的
        matching = [f for f in exps if base and base in f]
        return os.path.join(EXPLOITS_DIR, matching[0]) if matching else (
            os.path.join(EXPLOITS_DIR, exps[0]) if exps else None
        )
        return os.path.join(EXPLOITS_DIR, exps[0]) if exps else None
    
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
        """双击打开选中的exp"""
        sel = self.exp_listbox.curselection()
        if sel:
            exp_name = self.exp_listbox.get(sel[0])
            exp_path = os.path.join(EXPLOITS_DIR, exp_name)
            self._open_with_platform_default(exp_path)
    
    def _open_exp_folder(self):
        """打开exp文件夹"""
        self._open_with_platform_default(EXPLOITS_DIR)

    def _open_with_platform_default(self, path):
        if IS_WINDOWS:
            os.startfile(path)
        elif IS_MACOS:
            subprocess.Popen(['open', path])
        else:
            subprocess.Popen(['xdg-open', path])
    
    # ========== 主循环 ==========
    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    gui = PwnSolverGUI()
    gui.run()
