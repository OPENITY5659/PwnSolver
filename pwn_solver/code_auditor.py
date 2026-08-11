#!/usr/bin/env python3
"""
代码审计引擎 — 不依赖符号名，通过反汇编理解程序逻辑

功能:
1. 函数发现 (stripped binary支持)
2. 调用链追踪 (谁调用了危险函数)
3. 危险调用点定位 (gets/read/scanf的调用位置)
4. 栈帧分析 (局部变量大小)
5. Win路径发现 (谁调用了system/execve)
6. 控制流图简化
"""

import os, re, subprocess
from collections import defaultdict

class CodeAuditor:
    """二进制代码审计器"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = os.path.abspath(binary_path)
        self.verbose = verbose
        self._disasm = None
        self._functions = None
        self._call_graph = None
        
    def log(self, msg):
        if self.verbose:
            print(f"  [audit] {msg}", flush=True)
    
    def disassemble(self):
        """获取完整反汇编"""
        if self._disasm:
            return self._disasm
        
        self.log("反汇编中...")
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=60
            )
            self._disasm = result.stdout
            self.log(f"反汇编完成 ({len(self._disasm)} chars)")
        except Exception as e:
            self.log(f"反汇编失败: {e}")
            self._disasm = ""
        
        return self._disasm
    
    def find_functions(self):
        """发现所有函数（含stripped）"""
        if self._functions:
            return self._functions
        
        disasm = self.disassemble()
        functions = {}
        current_func = None
        
        for line in disasm.split('\n'):
            # 匹配函数标签: 0000000000401234 <function_name>:
            m = re.match(r'^([0-9a-f]+)\s+<([^>]+)>:\s*$', line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2)
                current_func = {'name': name, 'addr': addr, 'calls': [], 'called_by': []}
                functions[name] = current_func
                continue
            
            if current_func:
                # 匹配call指令: call 4005a0 <system@plt>
                m = re.search(r'call\s+(?:0x)?([0-9a-f]+)\s*(?:<([^>]+)>)?', line)
                if m:
                    target_addr = int(m.group(1), 16)
                    target_name = m.group(2) if m.group(2) else f"0x{target_addr:x}"
                    current_func['calls'].append((target_addr, target_name))
        
        self._functions = functions
        self.log(f"发现 {len(functions)} 个函数")
        return functions
    
    def find_dangerous_callsites(self):
        """找到所有危险函数的调用点"""
        functions = self.find_functions()
        dangerous_funcs = {'gets', 'scanf', 'read', 'fgets', 'strcpy', 
                          'strcat', 'sprintf', 'memcpy', 'gets@plt',
                          'read@plt', 'scanf@plt', 'fgets@plt'}
        win_funcs = {'system', 'execve', 'system@plt', 'execve@plt'}
        
        danger_sites = []
        win_sites = []
        
        for fname, finfo in functions.items():
            for target_addr, target_name in finfo['calls']:
                # 匹配危险函数
                for d in dangerous_funcs:
                    if d in target_name.lower():
                        danger_sites.append({
                            'caller': fname,
                            'caller_addr': finfo['addr'],
                            'target': target_name,
                            'target_addr': target_addr,
                            'type': 'dangerous_input',
                        })
                        break
                
                # 匹配win函数
                for w in win_funcs:
                    if w in target_name.lower():
                        win_sites.append({
                            'caller': fname,
                            'caller_addr': finfo['addr'],
                            'target': target_name,
                            'target_addr': target_addr,
                            'type': 'win_call',
                        })
                        break
        
        self.log(f"危险调用: {len(danger_sites)}, Win调用: {len(win_sites)}")
        return danger_sites, win_sites
    
    def trace_vulnerability_path(self):
        """追踪漏洞路径：从入口到危险调用"""
        danger_sites, win_sites = self.find_dangerous_callsites()
        functions = self.find_functions()
        
        paths = []
        
        # 找到main或_start作为入口
        entry = None
        for name in ['main', '_start', 'entry']:
            if name in functions:
                entry = name
                break
        
        for site in danger_sites:
            caller = site['caller']
            path = [caller]
            
            # 逆向追踪：谁调用了caller
            visited = set()
            current = caller
            while current != entry and current not in visited:
                visited.add(current)
                # 查找谁调用了current
                found = False
                for fname, finfo in functions.items():
                    for _, tname in finfo['calls']:
                        if current in tname or tname == current:
                            path.insert(0, fname)
                            current = fname
                            found = True
                            break
                    if found:
                        break
                if not found:
                    break
            
            paths.append({
                'entry': entry,
                'path': path,
                'danger_site': site,
                'has_win': any(w['caller'] in path for w in win_sites),
            })
        
        return paths
    
    def analyze_stack_frame(self, func_name):
        """分析指定函数的栈帧"""
        disasm = self.disassemble()
        
        # 找函数体
        func_start = -1
        func_end = -1
        lines = disasm.split('\n')
        
        for i, line in enumerate(lines):
            if f'<{func_name}>:' in line:
                func_start = i
            elif func_start >= 0 and re.match(r'^\s*$', line) and i > func_start + 3:
                func_end = i
                break
        
        if func_start < 0:
            return {'error': f'Function {func_name} not found'}
        
        # 分析开头部分
        frame_size = 0
        local_vars = []
        has_canary = False
        
        for i in range(func_start, min(func_start + 30, len(lines))):
            line = lines[i]
            # sub rsp, 0xNN
            m = re.search(r'sub\s+(?:rsp|esp),\s*(0x[0-9a-f]+)', line, re.I)
            if m:
                frame_size = int(m.group(1), 16)
            
            # push rbp; mov rbp, rsp
            if 'push' in line and ('rbp' in line or 'ebp' in line):
                pass
            
            # canary检测: mov rax, fs:0x28
            if 'fs:0x28' in line or 'fs:0x14' in line:
                has_canary = True
            
            # 局部变量引用: [rbp-0xNN] 或 [rbp+0xNN]
            m = re.search(r'\[(?:rbp|ebp)([+-])(0x[0-9a-f]+)\]', line, re.I)
            if m:
                offset = int(m.group(2), 16)
                if m.group(1) == '-':
                    local_vars.append(offset)
        
        return {
            'function': func_name,
            'frame_size': frame_size,
            'local_vars': sorted(set(local_vars), reverse=True),
            'has_canary': has_canary,
            'estimated_buffer': max(local_vars) if local_vars else frame_size,
        }
    
    def full_audit(self):
        """全量代码审计报告"""
        self.log("=" * 50)
        self.log("代码审计报告")
        self.log("=" * 50)
        
        functions = self.find_functions()
        danger, win = self.find_dangerous_callsites()
        
        report = {
            'total_functions': len(functions),
            'dangerous_callsites': danger,
            'win_callsites': win,
            'vulnerability_paths': self.trace_vulnerability_path(),
        }
        
        # 输出摘要
        self.log(f"函数总数: {len(functions)}")
        self.log(f"危险调用点: {len(danger)}")
        self.log(f"Win调用点: {len(win)}")
        
        if danger:
            self.log("\n漏洞路径分析:")
            for i, site in enumerate(danger[:5]):
                self.log(f"  [{i+1}] {site['caller']} → {site['target']}")
                # 分析栈帧
                frame = self.analyze_stack_frame(site['caller'])
                if frame.get('estimated_buffer'):
                    self.log(f"       栈帧: {hex(frame['frame_size'])}, "
                           f"缓冲区: {hex(frame['estimated_buffer'])}")
        
        if win:
            self.log(f"\nWin函数可达性:")
            for w in win[:5]:
                self.log(f"  {w['caller']} → {w['target']}")
        
        return report


def audit_binary(binary_path):
    """快速审计API"""
    auditor = CodeAuditor(binary_path, verbose=True)
    return auditor.full_audit()
