import os
import tempfile
import atexit
import readline
import subprocess
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
        self._current_io = None
        self._current_elf = None
        self._current_process = None
        self._current_gdb = None
        self._cwd_local = os.getcwd()
        self._cwd_remote = None
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
        cmd = parts[0].replace('-', '_') # allow 'set-target'
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
  
  [bold]파일 시스템:[/bold]
  - [cyan]ls[/cyan] [dim][path][/dim]: 현재 디렉토리의 파일/폴더 목록을 봅니다.
  - [cyan]cd[/cyan] [dim]<path>[/dim]: 작업 디렉토리를 변경합니다.
  - [cyan]pwd[/cyan]: 현재 작업 디렉토리를 표시합니다.

  [bold]연결:[/bold]
  - [cyan]connect[/cyan] [dim]<host> <port>[/dim]: 원격 서비스(TCP)에 연결합니다.
  - [cyan]ssh_to[/cyan] [dim]<user@host[:port]>[/dim]: SSH를 통해 원격 호스트에 연결합니다.
  - [cyan]disconnect[/cyan]: 현재 연결(TCP 또는 SSH)을 끊습니다.
  - [cyan]upload[/cyan] [dim]<local> <remote>[/dim]: (SSH 연결 시) 원격 호스트로 파일/폴더를 업로드합니다.

  [bold]분석 및 실행:[/bold]
  - [cyan]set_target[/cyan] [dim]<path>[/dim]: 분석할 대상 바이너리를 지정합니다.
  - [cyan]run[/cyan] [dim][args...][/dim]: 지정된 대상 바이너리를 실행합니다.
  - [cyan]interact[/cyan], [cyan]i[/cyan]: 현재 연결된 원격 서비스/프로세스와 상호작용합니다.
  - [cyan]send[/cyan] [dim]<data>[/dim]: 원격 서비스/프로세스에 데이터를 전송합니다.

  [bold]디버깅 (GDB):[/bold]
  - [cyan]gdb[/cyan]: 실행 중인 프로세스에 GDB를 연결합니다.
  - [cyan]gdb_cmd[/cyan] [dim]<gdb_command>[/dim]: GDB 명령어를 직접 실행합니다.
  - [cyan]c, n, s, b[/cyan]: GDB 실행을 제어합니다.

  [bold]익스플로잇:[/bold]
  - [cyan]exploit[/cyan] [dim][filename][/dim]: 익스플로잇 템플릿을 생성합니다.
"""
        self.console.print(Panel(help_text, title="도움말", border_style="panel_border"))

    def _get_full_path(self, path):
        # Check for absolute paths first
        if path.startswith('/') or (len(path) > 1 and path[1] == ':'): # Handles / and C: style paths
            return path

        if self._current_ssh:
            return os.path.join(self._cwd_remote, path)
        else:
            return os.path.join(self._cwd_local, path)

    def _cmd_ls(self, args):
        path = args[0] if args else "."
        full_path = self._get_full_path(path)
        
        try:
            if self._current_ssh:
                output = self._current_ssh.execute(f"ls -laF {sh_string(full_path)}").decode()
            else:
                output = subprocess.check_output(["ls", "-laF", full_path], text=True)
            self.console.print(output)
        except Exception as e:
            self.console.print(f"[error]목록 조회 실패: {e}[/error]")

    def _cmd_cd(self, args):
        if not args:
            self.console.print("[error]이동할 경로를 지정해주세요.[/error]")
            return
        path = " ".join(args)
        
        try:
            if self._current_ssh:
                # Execute 'cd' and then 'pwd' to get the new absolute path
                new_path_bytes = self._current_ssh.execute(f"cd {sh_string(self._get_full_path(path))} && pwd")
                new_path = new_path_bytes.decode().strip()
                self._cwd_remote = new_path
                self.console.print(f"[info]원격 작업 디렉토리 변경: [path]{self._cwd_remote}[/path][/info]")
            else:
                os.chdir(self._get_full_path(path))
                self._cwd_local = os.getcwd()
                self.console.print(f"[info]로컬 작업 디렉토리 변경: [path]{self._cwd_local}[/path][/info]")
        except Exception as e:
            self.console.print(f"[error]디렉토리 변경 실패: {e}[/error]")

    def _cmd_pwd(self, args):
        if self._current_ssh:
            self.console.print(f"[path]{self._cwd_remote}[/path]")
        else:
            self.console.print(f"[path]{self._cwd_local}[/path]")

    def _cmd_set_target(self, args):
        if not args:
            self.console.print("[error]사용법: set_target <file_path>[/error]")
            return
        
        target_path = self._get_full_path(args[0])
        
        try:
            if self._current_ssh:
                with self.console.status(f"원격 파일 다운로드 중: {target_path}...", spinner="dots"):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        self._current_ssh.download(target_path, tmp_file.name)
                        local_file_path = tmp_file.name
                atexit.register(os.remove, local_file_path)
                self.console.print(f"[success]임시 파일로 다운로드 완료: [path]{local_file_path}[/path][/success]")
            else:
                local_file_path = target_path
                if not os.path.exists(local_file_path):
                    self.console.print(f"[error]로컬 파일을 찾을 수 없습니다: [path]{local_file_path}[/path][/error]")
                    return

            self._current_elf = elf = ELF(local_file_path)
            self._current_elf.path = target_path # Store the original path for context
            self.console.print(f"[*] 대상 바이너리 지정 완료: [path]{target_path}[/path]")
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
            self.console.print(Panel("초기 정적 분석에서 명백한 취약점은 발견되지 않았습니다.", title="AI 분석 가이드", border_style="panel_border"))

    def _cmd_ssh_to(self, args):
        if not args:
            self.console.print("[error]사용법: ssh_to <user@host[:port]>[/error]")
            return
        
        try:
            user, host, port = self._parse_ssh_string(args[0])
            with self.console.status(f"{user}@{host}:{port}에 연결하는 중...", spinner="earth"):
                self._current_ssh = ssh(host=host, user=user, port=port)
                self._cwd_remote = self._current_ssh.pwd.decode().strip()
            self.console.print(f"[success][bold]{user}@{host}:{port}[/bold]에 연결되었습니다![/success]")
        except Exception as e:
            self.console.print(f"[error]SSH 연결 실패: {e}[/error]")

    def _cmd_connect(self, args):
        if len(args) != 2:
            self.console.print("[error]사용법: connect <host> <port>[/error]")
            return
        host, port_str = args
        try:
            port = int(port_str)
            with self.console.status(f"{host}:{port}에 연결하는 중...", spinner="earth"):
                self._current_io = remote(host, port)
            self.console.print(f"[success][bold]{host}:{port}[/bold]에 연결되었습니다! 'interact' 명령어로 상호작용하세요.[/success]")
        except Exception as e:
            self.console.print(f"[error]TCP 연결 실패: {e}[/error]")
    
    def _cmd_disconnect(self, args):
        disconnected = False
        if self._current_ssh:
            self._current_ssh.close()
            self._current_ssh = None
            disconnected = True
        if self._current_io:
            self._current_io.close()
            self._current_io = None
            disconnected = True
        
        if disconnected:
            self.console.print("[success]연결이 종료되었습니다.[/success]")
        else:
            self.console.print("[info]활성화된 연결이 없습니다.[/info]")

    def _cmd_upload(self, args):
        if not self._current_ssh:
            self.console.print("[error]SSH 연결이 필요합니다. 'ssh_to'를 먼저 사용하세요.[/error]")
            return
        if len(args) != 2:
            self.console.print("[error]사용법: upload <local_path> <remote_path>[/error]")
            return
        
        local_path, remote_path = self._get_full_path(args[0]), self._get_full_path(args[1])
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
        if self._current_io:
            self.console.print("[warning]이미 원격 서비스에 연결되어 있습니다. 'run' 대신 'interact' 또는 'send'를 사용하세요.[/warning]")
            return
        if not self._current_elf:
            self.console.print("[error]대상이 지정되지 않았습니다. 'set_target'을 먼저 사용하세요.[/error]")
            return
        
        try:
            self.console.print(f"[*] 프로세스 시작: [path]{self._current_elf.path}[/path] {' '.join(args)}")
            if self._current_ssh:
                # Use the original remote path for execution
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
        self._execute_gdb_cmd(lambda: self._current_gdb.break_(" ".join(args)))
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

    def _cmd_interact(self, args):
        target = self._current_io or self._current_process
        if not target:
            self.console.print("[error]상호작용할 연결 또는 프로세스가 없습니다.[/error]")
            return
        self.console.print(f"[info]'{target}'와 상호작용을 시작합니다... (Ctrl+C 후 Enter 또는 Ctrl+D로 종료)[/info]")
        target.interactive()
    def _cmd_i(self, args): self._cmd_interact(args)

    def _cmd_send(self, args):
        target = self._current_io or self._current_process
        if not target:
            self.console.print("[error]데이터를 보낼 연결 또는 프로세스가 없습니다.[/error]")
            return
        data_to_send = " ".join(args)
        try:
            target.sendline(data_to_send.encode())
            self.console.print(f"[info]전송 완료: {data_to_send!r}[/info]")
        except Exception as e:
            self.console.print(f"[error]전송 실패: {e}[/error]")

    def _cmd_exploit(self, args):
        if not self._current_elf:
            self.console.print("[error]대상이 지정되지 않았습니다. 'set_target'을 먼저 사용하세요.[/error]")
            return
        
        exploit_file_name = args[0] if args else "exploit.py"
        
        connect_host = "127.0.0.1"
        connect_port = 1337
        if self._current_io:
            connect_host = self._current_io.host
            connect_port = self._current_io.port
        elif self._current_ssh:
            connect_host = self._current_ssh.host
            # Defaulting to a common pwn port, not the SSH port
            connect_port = 1337 
        
        template = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# --- Gemini가 생성한 익스플로잇: {self._current_elf.path} ---
exe = context.binary = ELF('{self._current_elf.path}')
context.arch = '{self._current_elf.arch}'
# context.log_level = 'debug'

# --- 연결 정보 ---
HOST = '{connect_host}'
PORT = {connect_port}

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return connect(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b main
continue
'''.format(**locals())

# --- AI 분석 제안 ---
{self._get_ai_suggestions_for_exploit()}

# --- 익스플로잇 로직 (수정 필요) ---
io = start()
io.interactive()
"""
        try:
            with open(exploit_file_name, "w") as f:
                f.write(template)
            self.console.print(f"[success]익스플로잇 템플릿 생성 완료: [path]{exploit_file_name}[/path][/success]")
        except Exception as e:
            self.console.print(f"[error]익스플로잇 파일 생성 실패: {e}[/error]")

    def _get_ai_suggestions_for_exploit(self):
        # (This helper method remains the same)
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
                current_path = self._cwd_remote if self._current_ssh else self._cwd_local
                prompt_text = Text(f"({current_path}) ", style="prompt") + Text("pwnchain> ")
                command = self.console.input(prompt_text)
                if not command: continue
                if command.strip() == "exit": break
                self.handle_command(command.strip())
            except KeyboardInterrupt:
                self.console.print("\n('exit'를 입력하여 종료하세요)")
            except EOFError:
                break
        self.console.print("[bold green]안녕히 가세요![/bold green]")

def main():
    cli = PwnChainCLI()
    cli.run_cli()