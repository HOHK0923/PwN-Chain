import os
import tempfile
import atexit
import readline
from pwn import *
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.theme import Theme
from rich.text import Text

# --- ASCII Art Banner ---
BANNER = """
██████╗ ██╗    ██╗███╗   ██╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
██╔══██╗██║    ██║████╗  ██║██║  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
██████╔╝██║ █╗ ██║██╔██╗ ██║███████║██║     ███████║███████║██║██╔██╗ ██║
██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
██║     ╚███╔███╔╝██║ ╚████║██║  ██║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
Gemini 기반의 차세대 바이너리 분석 및 익스플로잇 도우미
"""

# --- Custom Theme ---
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "prompt": "bold cyan",
    "address": "bold magenta",
    "path": "bold blue",
    "panel_border": "dim blue"
})


class PwnChainCLI:
    """pwndbg 스타일의 바이너리 분석용 CLI입니다."""

    def __init__(self):
        self._current_ssh = None
        self._current_elf = None
        self._current_process = None
        self._current_gdb = None
        self.console = Console(theme=custom_theme)
        context.log_level = 'error'

    def _display_context(self):
        if not self._current_gdb or not self._current_process or not self._current_process.is_alive():
            return
        
        try:
            regs_table = Table(title="레지스터", show_header=False, box=None, padding=(0, 1))
            regs_table.add_column("Register", style="cyan")
            regs_table.add_column("Value", style="address")
            regs = self._current_gdb.execute("info registers", to_string=True).splitlines()
            for reg_line in regs:
                parts = reg_line.split()
                if len(parts) >= 2:
                    regs_table.add_row(parts[0], parts[1])
            
            disassembly_text = Text.from_ansi(self._current_gdb.execute("x/10i $pc", to_string=True))
            disasm_panel = Panel(disassembly_text, title="디스어셈블리", border_style="green", expand=True)

            stack_text = Text.from_ansi(self._current_gdb.execute("x/16xg $rsp", to_string=True))
            stack_panel = Panel(stack_text, title="스택", border_style="yellow", expand=True)

            self.console.print(Panel(Columns([disasm_panel, stack_panel, regs_table]), border_style="panel_border", title="GDB 컨텍스트"))
        except Exception as e:
            self.console.print(f"[error]컨텍스트 업데이트 오류: {e}[/error]")

    def handle_command(self, command_str):
        parts = command_str.split()
        if not parts: return
        cmd = parts[0]
        args = parts[1:]
        
        handler = getattr(self, f"_cmd_{cmd}", self._cmd_unknown)
        handler(args)

    def _cmd_unknown(self, args):
        self.console.print(f"[error]알 수 없는 명령어입니다.[/error]")

    def _cmd_help(self, args):
        help_text = """
[bold]사용 가능한 명령어:[/bold]
  - [cyan]help[/cyan]: 이 도움말 메시지를 표시합니다.
  - [cyan]exit[/cyan]: 애플리케이션을 종료합니다.
  - [cyan]connect[/cyan] [dim]<user@host[:port]>[/dim]: SSH를 통해 원격 호스트에 연결합니다.
  - [cyan]disconnect[/cyan]: 원격 호스트와의 연결을 끊습니다.
  - [cyan]upload[/cyan] [dim]<local> <remote>[/dim]: 원격 호스트로 파일 또는 폴더를 업로드합니다.
  - [cyan]load[/cyan] [dim]<path>[/dim]: 분석할 바이너리(로컬 또는 원격)를 로드합니다.
  - [cyan]run[/cyan] [dim][args...][/dim]: 로드된 바이너리를 실행합니다.
  - [cyan]gdb[/cyan]: 실행 중인 프로세스에 GDB를 연결합니다.
  - [cyan]gdb_cmd[/cyan] [dim]<gdb_command>[/dim]: GDB 명령어를 직접 실행합니다.
  - [cyan]c, cont, continue[/cyan]: GDB에서 실행을 계속합니다.
  - [cyan]n, next[/cyan]: GDB에서 다음 명령어로 스텝 오버합니다.
  - [cyan]s, si, step, stepi[/cyan]: GDB에서 다음 명령어로 스텝 인합니다.
  - [cyan]b, break[/cyan] [dim]<target>[/dim]: GDB에 중단점을 설정합니다.
  - [cyan]exploit[/cyan] [dim][filename][/dim]: pwntools 익스플로잇 템플릿을 생성합니다.
"""
        self.console.print(Panel(help_text, title="도움말", border_style="panel_border"))

    def _cmd_load(self, args):
        if not args:
            self.console.print("[error]사용법: load <file_path>[/error]")
            return
        
        remote_file_path = args[0]
        
        try:
            if self._current_ssh:
                with self.console.status(f"원격 파일 다운로드 중: {remote_file_path}...", spinner="dots"):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        self._current_ssh.download(remote_file_path, tmp_file.name)
                        local_file_path = tmp_file.name
                atexit.register(os.remove, local_file_path)
                self.console.print(f"[success]임시 파일로 다운로드 완료: [path]{local_file_path}[/path][/success]")
            else:
                local_file_path = remote_file_path
                if not os.path.exists(local_file_path):
                    self.console.print(f"[error]로컬 파일을 찾을 수 없습니다: [path]{local_file_path}[/path][/error]")
                    return

            self._current_elf = elf = ELF(local_file_path)
            self.console.print(f"[*] 바이너리 로드 완료: [path]{remote_file_path}[/path]")
            self._run_ai_analysis(elf)

        except Exception as e:
            self.console.print(f"[error]바이너리 분석 실패: {e}[/error]")

    def _run_ai_analysis(self, elf):
        checksec_result = elf.checksec(banner=False)
        self.console.print(Panel(str(checksec_result), title="Checksec", border_style="panel_border"))
        
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("- [warning]카나리(Canary) 없음:[/warning] 스택 버퍼 오버플로우에 취약할 수 있습니다.")
        if not checksec_result.get('NX'):
            suggestions.append("- [warning]NX 비활성화:[/warning] 스택 또는 힙 영역에서의 셸코드 실행이 가능할 수 있습니다.")
        if not checksec_result.get('PIE'):
            suggestions.append("- [info]PIE 비활성화:[/info] 바이너리 주소 공간이 고정되어 ROP/ret2libc 공격이 용이합니다.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found_dangerous = [func for func in dangerous_functions if func in elf.symbols or func in elf.plt]
        if found_dangerous:
            suggestions.append(f"- [warning]위험 함수 발견:[/warning] {', '.join(found_dangerous)}. 해당 함수의 사용을 주의 깊게 살펴보세요.")

        if suggestions:
            self.console.print(Panel("\n".join(suggestions), title="AI 분석 가이드", border_style="panel_border"))
        else:
            self.console.print(Panel("초기 정적 분석에서 명백한 취약점은 발견되지 않았습니다. 로직 상의 허점이나 다른 종류의 취약점을 찾아보세요.", title="AI 분석 가이드", border_style="panel_border"))

    def _cmd_connect(self, args):
        if not args:
            self.console.print("[error]사용법: connect <user@host[:port]>[/error]")
            return
        
        try:
            user, host, port = self._parse_ssh_string(args[0])
            with self.console.status(f"{user}@{host}:{port}에 연결하는 중...", spinner="earth"):
                self._current_ssh = ssh(host=host, user=user, port=port)
            self.console.print(f"[success][bold]{user}@{host}:{port}[/bold]에 연결되었습니다![/success]")
        except Exception as e:
            self.console.print(f"[error]연결 실패: {e}[/error]")

    def _cmd_disconnect(self, args):
        if self._current_ssh:
            self._current_ssh.close()
            self._current_ssh = None
            self.console.print("[success]연결이 종료되었습니다.[/success]")
        else:
            self.console.print("[info]연결된 호스트가 없습니다.[/info]")

    def _cmd_upload(self, args):
        if not self._current_ssh:
            self.console.print("[error]연결된 호스트가 없습니다. 'connect'를 먼저 사용하세요.[/error]")
            return
        if len(args) != 2:
            self.console.print("[error]사용법: upload <local_path> <remote_path>[/error]")
            return
        
        local_path, remote_path = args
        if not os.path.exists(local_path):
            self.console.print(f"[error]로컬 경로를 찾을 수 없습니다: [path]{local_path}[/path][/error]")
            return
        
        try:
            with self.console.status(f"'{local_path}' 업로드 중...", spinner="arc"):
                self._current_ssh.upload(local_path, remote_path)
            self.console.print(f"[success]업로드 성공.[/success]")
        except Exception as e:
            self.console.print(f"[error]업로드 실패: {e}[/error]")

    def _cmd_run(self, args):
        if not self._current_elf:
            self.console.print("[error]로드된 바이너리가 없습니다.[/error]")
            return
        
        try:
            self.console.print(f"[*] 프로세스 시작: [path]{self._current_elf.path}[/path] {' '.join(args)}")
            if self._current_ssh:
                self._current_process = self._current_ssh.process([self._current_elf.path] + args)
            else:
                self._current_process = process([self._current_elf.path] + args)
            self.console.print(f"[success]프로세스 시작됨 (PID: {self._current_process.pid})[/success]")
        except Exception as e:
            self.console.print(f"[error]프로세스 실행 실패: {e}[/error]")

    def _cmd_gdb(self, args):
        if not self._current_process or not self._current_process.is_alive():
            self.console.print("[error]연결할 실행 중인 프로세스가 없습니다.[/error]")
            return
        try:
            self.console.print(f"[*] GDB 연결 시도 (PID: {self._current_process.pid})...")
            self._current_gdb = gdb.attach(self._current_process)
            self.console.print("[success]GDB 연결됨.[/success]")
            self._display_context()
        except Exception as e:
            self.console.print(f"[error]GDB 연결 실패: {e}[/error]")

    def _execute_gdb_cmd(self, cmd_func):
        if not self._current_gdb:
            self.console.print("[error]GDB가 연결되어 있지 않습니다.[/error]")
            return
        try:
            with self.console.status("GDB 명령어 실행 중...", spinner="line"):
                cmd_func()
            self._display_context()
        except Exception as e:
            self.console.print(f"[error]GDB 명령어 실패: {e}[/error]")

    def _cmd_c(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.cont())
    def _cmd_cont(self, args): self._cmd_c(args)
    def _cmd_continue(self, args): self._cmd_c(args)
    
    def _cmd_n(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.next())
    def _cmd_next(self, args): self._cmd_n(args)

    def _cmd_s(self, args): self._execute_gdb_cmd(lambda: self._current_gdb.step())
    def _cmd_si(self, args): self._cmd_s(args)
    def _cmd_step(self, args): self._cmd_s(args)
    def _cmd_stepi(self, args): self._cmd_s(args)

    def _cmd_b(self, args):
        if not args:
            self.console.print("[error]사용법: break <address/function_name>[/error]")
            return
        self._execute_gdb_cmd(lambda: self._current_gdb.break_(args[0]))
    def _cmd_break(self, args): self._cmd_b(args)

    def _cmd_gdb_cmd(self, args):
        if not self._current_gdb:
            self.console.print("[error]GDB가 연결되어 있지 않습니다.[/error]")
            return
        try:
            result = self._current_gdb.execute(" ".join(args), to_string=True)
            self.console.print(result)
        except Exception as e:
            self.console.print(f"[error]GDB 명령어 실패: {e}[/error]")

    def _cmd_exploit(self, args):
        if not self._current_elf:
            self.console.print("[error]로드된 바이너리가 없습니다.[/error]")
            return
        
        exploit_file_name = args[0] if args else "exploit.py"
        connect_host = self._current_ssh.host if self._current_ssh else "127.0.0.1"
        connect_port = self._current_ssh.port if self._current_ssh else 1337

        template = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# --- Gemini가 생성한 익스플로잇: {self._current_elf.path} ---
exe = context.binary = ELF('{self._current_elf.path}')
context.arch = '{self._current_elf.arch}'
# context.log_level = 'debug' # 디버그 로그 활성화

# --- 연결 정보 ---
HOST = '{connect_host}'
PORT = {connect_port}

def start(argv=[], *a, **kw):
    '''타겟 프로세스 시작'''
    if args.REMOTE:
        return connect(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# --- GDB 스크립트 ---
gdbscript = '''
b main
continue
'''.format(**locals())

# --- AI 분석 제안 ---
{self._get_ai_suggestions_for_exploit()}

# --- 익스플로잇 로직 (수정 필요) ---
io = start()

# 예시: 버퍼 오버플로우 (카나리가 없는 경우)
# from pwnlib.util.cyclic import cyclic, cyclic_find
# offset = cyclic_find(b'...') # GDB에서 `cyclic 200`, `run`, `p $rsp` 등으로 오프셋 찾기
# payload = flat(
#     b'A' * offset,
#     p64(0xdeadbeef) # 반환 주소 (예: exe.sym.win_function)
# )

# 페이로드 전송
# io.sendline(payload)

io.interactive()"""
        try:
            with open(exploit_file_name, "w") as f:
                f.write(template)
            self.console.print(f"[success]익스플로잇 템플릿 생성 완료: [path]{exploit_file_name}[/path][/success]")
        except Exception as e:
            self.console.print(f"[error]익스플로잇 파일 생성 실패: {e}[/error]")

    def _get_ai_suggestions_for_exploit(self):
        if not self._current_elf: return ""
        
        checksec_result = self._current_elf.checksec(banner=False)
        suggestions = []
        if not checksec_result.get('Canary'):
            suggestions.append("# - 카나리 없음 -> 스택 버퍼 오버플로우에 취약할 가능성이 높습니다.")
        if not checksec_result.get('NX'):
            suggestions.append("# - NX 비활성화 -> 셸코드 주입이 가능한 공격 벡터입니다.")
        if not checksec_result.get('PIE'):
            suggestions.append("# - PIE 비활성화 -> 고정 주소를 사용하므로 ROP/ret2libc 공격이 용이합니다.")
        
        dangerous_functions = ['gets', 'strcpy', 'sprintf', 'system']
        found = [func for func in dangerous_functions if func in self._current_elf.symbols or func in self._current_elf.plt]
        if found:
            suggestions.append(f"# - 위험 함수 발견: {', '.join(found)}.")
        
        return "\n".join(suggestions)

    def _parse_ssh_string(self, connect_str):
        user_host, *port_part = connect_str.split(':')
        user, host = user_host.split('@')
        port = int(port_part[0]) if port_part else 22
        return user, host, port

    def run_cli(self):
        self.console.print(Panel(BANNER, border_style="green", expand=False))
        self.console.print("PwnChain CLI에 오신 것을 환영합니다! 'help'를 입력하여 명령어 목록을 확인하세요.")
        while True:
            try:
                command = input("pwnchain> ").strip()
                if not command: continue
                if command == "exit": break
                self.handle_command(command)
            except KeyboardInterrupt:
                self.console.print("\n('exit'를 입력하여 종료하세요)")
            except EOFError:
                break
        self.console.print("[bold green]안녕히 가세요![/bold green]")

def main():
    cli = PwnChainCLI()
    cli.run_cli()
