#!/usr/bin/env python3
"""
LibcSearcher集成模块
通过泄露的函数地址自动匹配并下载正确的libc
"""

import os
import sys

class LibcMatcher:
    """Libc自动匹配器"""
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self._searcher = None
        
    def log(self, msg):
        if self.verbose:
            print(f"  [libc] {msg}", flush=True)
    
    def search_by_leak(self, func_name, leaked_addr):
        """
        通过泄露的函数地址搜索匹配的libc
        返回: (libc_path, base_addr) 或 (None, None)
        """
        try:
            from LibcSearcher import LibcSearcher
            
            self.log(f"LibcSearcher: {func_name} @ {hex(leaked_addr)}")
            obj = LibcSearcher(func_name, leaked_addr)
            
            # 获取匹配的libc
            if hasattr(obj, 'db') and obj.db:
                libc_path = obj.db
                base_addr = leaked_addr - obj.dump(func_name)
                self.log(f"匹配libc: {os.path.basename(libc_path)}")
                self.log(f"libc base: {hex(base_addr)}")
                return libc_path, base_addr
            
            # 尝试手动下载
            if hasattr(obj, 'download'):
                libc_path = obj.download()
                if libc_path:
                    base_addr = leaked_addr - obj.dump(func_name)
                    self.log(f"下载libc: {os.path.basename(libc_path)}")
                    self.log(f"libc base: {hex(base_addr)}")
                    return libc_path, base_addr
            
            self.log("未找到匹配的libc")
            return None, None
            
        except ImportError:
            self.log("LibcSearcher未安装 (pip install LibcSearcher)")
            return None, None
        except Exception as e:
            self.log(f"LibcSearcher错误: {e}")
            return None, None
    
    def find_by_symbols(self, symbol_offsets):
        """
        通过多个符号偏移搜索libc
        symbol_offsets: {'puts': 0x890, '__libc_start_main': 0x240, ...}
        返回匹配的libc路径
        """
        try:
            from LibcSearcher import LibcSearcher
            
            for sym, offset_low12 in symbol_offsets.items():
                if not offset_low12:
                    continue
                # 尝试用每个符号的最后12位去搜索
                # LibcSearcher需要实际泄露地址，这里用偏移模拟
                fake_addr = 0x7f0000000000 | offset_low12
                try:
                    obj = LibcSearcher(sym, fake_addr)
                    if hasattr(obj, 'db') and obj.db:
                        self.log(f"通过{sym}(0x{offset_low12:03x})匹配: {os.path.basename(obj.db)}")
                        return obj.db, obj
                except:
                    continue
            
            return None, None
        except Exception as e:
            self.log(f"搜索失败: {e}")
            return None, None
    
    def get_common_libc_db_path(self):
        """获取常见的libc数据库路径"""
        paths = [
            os.path.expanduser('~/.libcsearcher'),
            os.path.expanduser('~/LibcSearcher'),
            '/usr/share/libc-database',
            os.path.join(os.path.dirname(__file__), 'libc_db'),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None


def create_libc_resolver_script(leak_func, libc_path=None):
    """
    生成内联的libc解析代码（用于exploit模板）
    不依赖外部LibcSearcher模块
    """
    if libc_path:
        return f'''
# 使用指定的libc
libc = ELF("{libc_path}")
libc.address = leaked - libc.symbols['{leak_func}']
log.success(f"libc base: {{hex(libc.address)}}")
'''
    else:
        return f'''
# 尝试用LibcSearcher自动匹配libc
try:
    from LibcSearcher import LibcSearcher
    obj = LibcSearcher("{leak_func}", leaked)
    if hasattr(obj, 'dump'):
        libc_base = leaked - obj.dump("{leak_func}")
        log.success(f"LibcSearcher: libc base = {{hex(libc_base)}}")
        # 尝试获取system和/bin/sh
        system_off = obj.dump("system")
        binsh_off = obj.dump("str_bin_sh")
        if system_off and binsh_off:
            system = libc_base + system_off
            binsh = libc_base + binsh_off
            log.info(f"system: {{hex(system)}}, /bin/sh: {{hex(binsh)}}")
        libc = obj  # 作为偏移查找器使用
    else:
        log.error("LibcSearcher failed, need manual libc")
        exit(1)
except ImportError:
    log.error("pip install LibcSearcher first!")
    exit(1)
'''
