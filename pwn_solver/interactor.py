#!/usr/bin/env python3
"""
交互模块
处理与本地/远程二进制文件的IO
"""

import os
import time
from pwn import process, remote, context


class BinaryInteractor:
    """与目标二进制文件交互"""
    
    def __init__(self, binary_path, remote_target=None, verbose=True):
        self.binary_path = binary_path
        self.remote_target = remote_target  # (host, port)
        self.verbose = verbose
        self.p = None
        
    def log(self, msg):
        if self.verbose:
            print(f"  [io] {msg}", flush=True)
    
    def start(self, env=None, aslr=True):
        """启动进程"""
        if self.remote_target:
            host, port = self.remote_target
            self.log(f"连接远程: {host}:{port}")
            self.p = remote(host, int(port))
        else:
            self.log(f"启动本地进程: {self.binary_path}")
            env_dict = env or {}
            if not aslr:
                env_dict['LD_PRELOAD'] = ''
            self.p = process(self.binary_path, env=env_dict)
        
        return self.p
    
    def send(self, data):
        """发送数据"""
        if isinstance(data, str):
            data = data.encode()
        self.p.send(data)
    
    def sendline(self, data):
        """发送一行"""
        if isinstance(data, str):
            data = data.encode()
        self.p.sendline(data)
    
    def recv(self, n=4096, timeout=2):
        """接收数据"""
        try:
            return self.p.recv(n, timeout=timeout)
        except Exception:
            return b''
    
    def recvline(self, timeout=2):
        """接收一行"""
        try:
            return self.p.recvline(timeout=timeout)
        except Exception:
            return b''
    
    def recvuntil(self, delims, timeout=5):
        """接收直到特定字符串"""
        try:
            return self.p.recvuntil(delims, timeout=timeout)
        except Exception:
            return b''
    
    def recvall(self, timeout=3):
        """接收所有数据"""
        try:
            return self.p.recvall(timeout=timeout)
        except Exception:
            return b''
    
    def interactive(self):
        """进入交互模式"""
        self.p.interactive()
    
    def close(self):
        """关闭连接"""
        if self.p:
            self.p.close()
            self.p = None
    
    def send_after(self, delim, data):
        """等待特定提示后发送数据"""
        self.recvuntil(delim)
        self.send(data)
    
    def sendline_after(self, delim, data):
        """等待特定提示后发送一行"""
        self.recvuntil(delim)
        self.sendline(data)
    
    def try_shell(self, timeout=3):
        """尝试获取shell"""
        try:
            self.sendline(b'echo PWNED')
            time.sleep(0.5)
            response = self.recv(timeout=timeout)
            return b'PWNED' in response
        except Exception:
            return False
    
    def try_cat_flag(self, timeout=3):
        """尝试读取flag"""
        try:
            self.sendline(b'cat flag* 2>/dev/null; cat /flag* 2>/dev/null; cat ~/flag* 2>/dev/null')
            time.sleep(0.5)
            response = self.recv(timeout=timeout)
            return response
        except Exception:
            return b''
