#!/usr/bin/env python3
"""
BadChars检测与绕过引擎 + 自动libc检测
"""
from pwn import *
import os, glob, time

class BadCharsDetector:
    """自动检测bad characters"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = binary_path
        self.verbose = verbose
        self.badchars = set()
        
    def log(self, msg):
        if self.verbose:
            print(f"  [badchars] {msg}", flush=True)
    
    def detect(self):
        """发送0x00-0xff检测哪些被过滤"""
        self.log("检测bad characters...")
        try:
            p = process(self.binary_path)
            all_bytes = bytes(range(256))
            p.send(all_bytes + b'\n')
            time.sleep(0.5)
            try:
                resp = p.recvall(timeout=2)
            except:
                resp = b''
            p.close()
            
            self.badchars = set()
            for i in range(256):
                b = bytes([i])
                if b not in resp:
                    self.badchars.add(i)
            
            common = [b for b in [0x00, 0x0a, 0x20, 0x7f] if b in self.badchars]
            self.log(f"找到 {len(self.badchars)} 个bad chars: {[hex(b) for b in sorted(common)]}")
        except Exception as e:
            self.log(f"检测失败: {e}")
        
        return self.badchars
    
    def find_xor_key(self, target_bytes, max_xor=255):
        """找XOR密钥避开所有badchars"""
        for key in range(1, max_xor):
            encoded = bytes(b ^ key for b in target_bytes)
            if not any(b in self.badchars for b in encoded):
                return key
        return None
    
    def is_clean(self, data):
        """检查数据是否不含badchars"""
        return not any(b in self.badchars for b in data)


def auto_detect_libc(binary_path):
    """自动检测同目录下的libc文件"""
    binary_dir = os.path.dirname(os.path.abspath(binary_path))
    binary_name = os.path.basename(binary_path)
    candidates = []
    
    for f in glob.glob(os.path.join(binary_dir, '*')):
        name = os.path.basename(f)
        if name == binary_name: continue  # 跳过自身
        if 'ld-linux' in name: continue   # 跳过链接器
        if name.startswith('core.'): continue  # 跳过core dump
        if not os.path.isfile(f): continue
        try:
            with open(f, 'rb') as fp:
                if fp.read(4) == b'\x7fELF':
                    bn = name.lower()
                    # 精确匹配 libc.so, libc-2.31.so 等，排除 libcrypto/libc++/libcapstone/musl
                    if bn.startswith('libc') and (bn == 'libc' or bn.startswith('libc.so') or bn.startswith('libc-')):
                        return f
        except: pass
    
    return None  # 只返回明确命名的libc，不fallback到随机ELF
